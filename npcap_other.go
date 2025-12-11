//go:build !windows

package main

func isNpcapInstalled() bool {
	// Npcap is only for Windows, so we can assume it's not needed on other systems.
	return true
}

func installNpcap() error {
	// Nothing to do on non-Windows systems.
	return nil
}
