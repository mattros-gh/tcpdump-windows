//go:build windows

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/net/html"
)

const npcapDriverPath = `C:\Windows\System32\drivers\npcap.sys`
const npcapDownloadPage = "https://npcap.com/"

func isNpcapInstalled() bool {
	if _, err := os.Stat(npcapDriverPath); err == nil {
		return true
	}
	return false
}

func getLatestNpcapURL() (string, error) {
	base, err := url.Parse(npcapDownloadPage)
	if err != nil {
		return "", fmt.Errorf("failed to parse base URL: %w", err)
	}

	resp, err := http.Get(npcapDownloadPage)
	if err != nil {
		return "", fmt.Errorf("failed to get npcap download page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get npcap download page: status code %d", resp.StatusCode)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to parse npcap download page: %w", err)
	}

	var installerURL *url.URL
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" && strings.HasSuffix(a.Val, ".exe") && strings.Contains(a.Val, "npcap-") {
					rel, err := url.Parse(a.Val)
					if err == nil {
						installerURL = base.ResolveReference(rel)
					}
					return
				}
			}
		}
		for c := n.FirstChild; c != nil && installerURL == nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	if installerURL == nil {
		return "", fmt.Errorf("could not find npcap installer URL on download page")
	}

	return installerURL.String(), nil
}

func installNpcap() error {
	fmt.Println("Npcap is not installed. Downloading the installer...")

	installerURL, err := getLatestNpcapURL()
	if err != nil {
		return fmt.Errorf("failed to get latest npcap installer URL: %w", err)
	}
	fmt.Printf("Downloading from %s\n", installerURL)

	// Create a temporary file to download the installer to
	tmpFile, err := os.CreateTemp("", "npcap-installer-*.exe")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	// Do not remove the file immediately, the user needs to run it.
	// defer os.Remove(tmpFile.Name())

	// Download the installer
	resp, err := http.Get(installerURL)
	if err != nil {
		return fmt.Errorf("failed to download installer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download installer: status code %d", resp.StatusCode)
	}

	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save installer: %w", err)
	}
	tmpFile.Close() // Close the file so the installer can be run

	// Run the installer
	fmt.Printf("Installer downloaded to %s\n", tmpFile.Name())
	fmt.Println("Please run the installer to install Npcap, then restart this application.")

	cmd := exec.Command("cmd", "/C", "start", tmpFile.Name())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to open installer. Please open it manually from %s", tmpFile.Name())
	}

	// We can't proceed until Npcap is installed, so we exit here.
	os.Exit(0)

	return nil
}
