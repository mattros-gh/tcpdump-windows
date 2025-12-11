package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/pflag"
)

var (
	iface      = pflag.StringP("interface", "i", "", "Interface to listen on. If not specified, the first available interface will be used.")
	listIfaces = pflag.BoolP("list-interfaces", "D", false, "List available interfaces and exit.")
	verbose    = pflag.BoolP("verbose", "v", false, "Print verbose output.")
	writeFile  = pflag.StringP("write", "w", "", "Write the raw packets to the given file.")
)

func main() {
	pflag.Parse()

	printBanner()

	filter := strings.Join(pflag.Args(), " ")

	if !isNpcapInstalled() {
		if err := installNpcap(); err != nil {
			log.Fatalf("Failed to install Npcap: %v. Please install it manually.", err)
		}
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if *listIfaces {
		printInterfaces(devices)
		os.Exit(0)
	}

	var selectedDevice pcap.Interface
	if *iface == "" {
		if len(devices) > 0 {
			selectedDevice = devices[0]
		} else {
			log.Fatal("No interfaces found.")
		}
	} else {
		if num, err := strconv.Atoi(*iface); err == nil {
			if num > 0 && num <= len(devices) {
				selectedDevice = devices[num-1]
			} else {
				log.Fatalf("Invalid interface number: %d", num)
			}
		} else {
			found := false
			for _, device := range devices {
				if device.Name == *iface {
					selectedDevice = device
					found = true
					break
				}
			}
			if !found {
				log.Fatalf("Invalid interface name: %s", *iface)
			}
		}
	}

	log.Printf("Starting capture on interface %s", selectedDevice.Name)

	handle, err := pcap.OpenLive(selectedDevice.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatal(err)
		}
	}

	var w *pcapgo.Writer
	if *writeFile != "" {
		f, err := os.Create(*writeFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = pcapgo.NewWriter(f)
		if err := w.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
			log.Fatal(err)
		}
	}

	packetCache := make(map[string]struct{})
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		select {
		case <-ticker.C:
			// Clear the cache every 5 seconds to prevent it from growing too large
			packetCache = make(map[string]struct{})
		default:
		}

		signature := generateSignature(packet)
		if _, exists := packetCache[signature]; !exists {
			packetCache[signature] = struct{}{}

			if w != nil {
				if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					log.Printf("Error writing packet: %v", err)
				}
			}
			if *writeFile == "" {
				fmt.Println(formatPacket(packet, *verbose))
			}
		}
	}
}

func generateSignature(packet gopacket.Packet) string {
	hash := sha256.Sum256(packet.Data())
	return string(hash[:])
}

func printInterfaces(devices []pcap.Interface) {
	fmt.Println("Available interfaces:")
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Name)
		fmt.Printf("   Description: %s\n", device.Description)
		for _, address := range device.Addresses {
			fmt.Printf("   - IP address: %s\n", address.IP)
		}
	}
}

func formatPacket(packet gopacket.Packet, verbose bool) string {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	var output strings.Builder
	output.WriteString(timestamp + " ")

	if verbose {
		// Verbose output
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ipv4 := ipLayer.(*layers.IPv4)
			output.WriteString(fmt.Sprintf("IP (tos 0x%x, ttl %d, id %d, offset %d, flags [%s], proto %s (%d), length %d)\n",
				ipv4.TOS, ipv4.TTL, ipv4.Id, ipv4.FragOffset, ipFlags(ipv4), ipv4.Protocol, ipv4.Protocol, ipv4.Length))
			output.WriteString(fmt.Sprintf("    %s > %s: ", ipv4.SrcIP, ipv4.DstIP))
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ipv6 := ip6Layer.(*layers.IPv6)
			output.WriteString(fmt.Sprintf("IP6 (flowlabel 0x%x, hlim %d, next-header %s (%d) payload length: %d)\n",
				ipv6.FlowLabel, ipv6.HopLimit, ipv6.NextHeader, ipv6.NextHeader, ipv6.Length))
			output.WriteString(fmt.Sprintf("    %s > %s: ", ipv6.SrcIP, ipv6.DstIP))
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			output.WriteString(fmt.Sprintf("Flags [%s], cksum 0x%x, seq %d:%d, ack %d, win %d, length %d",
				tcpFlags(tcp), tcp.Checksum, tcp.Seq, tcp.Seq+uint32(len(tcp.Payload)), tcp.Ack, tcp.Window, len(tcp.Payload)))
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				if summary := decodeHTTP(appLayer.Payload(), true); summary != "" {
					output.WriteString(": HTTP, length: " + strconv.Itoa(len(appLayer.Payload())) + "\n\t" + summary)
				}
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			output.WriteString(fmt.Sprintf("UDP, length %d", udp.Length-8))
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns := dnsLayer.(*layers.DNS)
				for _, q := range dns.Questions {
					output.WriteString(fmt.Sprintf("\n        %d+ %s? %s.", dns.ID, q.Type, q.Name))
				}
			}
		} else if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
			icmp4, _ := icmp4Layer.(*layers.ICMPv4)
			output.WriteString(fmt.Sprintf("ICMPv4, %s", icmp4.TypeCode))
		} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
			icmp6, _ := icmp6Layer.(*layers.ICMPv6)
			output.WriteString(fmt.Sprintf("ICMPv6, %s", icmp6.TypeCode))
		} else {
			output.WriteString(fmt.Sprintf("length %d", packet.Metadata().Length))
		}
	} else {
		// Non-verbose output
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ipv4 := ipLayer.(*layers.IPv4)
			output.WriteString(fmt.Sprintf("IP %s > %s: ", ipv4.SrcIP, ipv4.DstIP))
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ipv6 := ip6Layer.(*layers.IPv6)
			output.WriteString(fmt.Sprintf("IP6 %s > %s: ", ipv6.SrcIP, ipv6.DstIP))
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			output.WriteString(fmt.Sprintf("TCP %d > %d Flags [%s] length %d", tcp.SrcPort, tcp.DstPort, tcpFlags(tcp), len(tcp.Payload)))
			if tcp.DstPort == 80 || tcp.SrcPort == 80 { // Common HTTP ports
				if appLayer := packet.ApplicationLayer(); appLayer != nil {
					if summary := decodeHTTP(appLayer.Payload(), false); summary != "" {
						output.WriteString(": HTTP: " + summary)
					}
				}
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			output.WriteString(fmt.Sprintf("UDP %d > %d length %d", udp.SrcPort, udp.DstPort, udp.Length-8))
		} else if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
			icmp4, _ := icmp4Layer.(*layers.ICMPv4)
			output.WriteString(fmt.Sprintf("ICMPv4 %s", icmp4.TypeCode))
		} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
			icmp6, _ := icmp6Layer.(*layers.ICMPv6)
			output.WriteString(fmt.Sprintf("ICMPv6 %s", icmp6.TypeCode))
		} else {
			output.WriteString(fmt.Sprintf("length %d", packet.Metadata().Length))
		}
	}
	return output.String()
}

func tcpFlags(tcp *layers.TCP) string {
	var flags []string
	if tcp.FIN {
		flags = append(flags, "F")
	}
	if tcp.SYN {
		flags = append(flags, "S")
	}
	if tcp.RST {
		flags = append(flags, "R")
	}
	if tcp.PSH {
		flags = append(flags, "P")
	}
	if tcp.ACK {
		flags = append(flags, ".")
	}
	if tcp.URG {
		flags = append(flags, "U")
	}
	return strings.Join(flags, "")
}

func ipFlags(ipv4 *layers.IPv4) string {
	var flags []string
	if ipv4.Flags&layers.IPv4DontFragment != 0 {
		flags = append(flags, "DF")
	}
	if ipv4.Flags&layers.IPv4MoreFragments != 0 {
		flags = append(flags, "MF")
	}
	if len(flags) == 0 {
		return "none"
	}
	return strings.Join(flags, ",")
}

func decodeHTTP(payload []byte, verbose bool) string {
	reader := bufio.NewReader(strings.NewReader(string(payload)))
	if !verbose {
		line, err := reader.ReadString('\n')
		if err != nil {
			return ""
		}
		return strings.TrimSpace(line)
	}

	var httpHeaders strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		httpHeaders.WriteString(line + "\n\t")
	}
	return httpHeaders.String()
}

func printBanner() {
	fmt.Println("\n\n*******************************************************\n" +
	"tcpdump for Windows written by Matt Roszel\n" +
	"matt@b-compservices.com\n" +
	"*******************************************************\n\n")
}
