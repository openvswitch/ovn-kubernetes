package util

import (
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"time"
)

// GenerateMac generates mac address.
func GenerateMac() string {
	prefix := "00:00:00"
	newRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	mac := fmt.Sprintf("%s:%02X:%02X:%02X", prefix, newRand.Intn(255), newRand.Intn(255), newRand.Intn(255))
	return mac
}

// NextIP returns IP incremented by 1
func NextIP(ip net.IP) net.IP {
	i := ipToInt(ip)
	return intToIP(i.Add(i, big.NewInt(1)))
}

func ipToInt(ip net.IP) *big.Int {
	if v := ip.To4(); v != nil {
		return big.NewInt(0).SetBytes(v)
	}
	return big.NewInt(0).SetBytes(ip.To16())
}

func intToIP(i *big.Int) net.IP {
	return net.IP(i.Bytes())
}

// GetPortAddresses returns the MAC and IP of the given logical switch port
func GetPortAddresses(portName string) (net.HardwareAddr, net.IP, error) {
	out, _, err := RunOVNNbctl("get", "logical_switch_port", portName, "dynamic_addresses")
	if err != nil {
		return nil, nil, fmt.Errorf("Error while obtaining addresses for %s: %v", portName, err)
	}
	if out == "[]" {
		// No addresses
		return nil, nil, nil
	}

	// dynamic addresses have format "0a:00:00:00:00:01 192.168.1.3".
	outStr := strings.Trim(out, `"`)
	addresses := strings.Split(outStr, " ")
	if len(addresses) != 2 {
		return nil, nil, fmt.Errorf("Error while obtaining addresses for %s", portName)
	}
	ip := net.ParseIP(addresses[1])
	if ip == nil {
		return nil, nil, fmt.Errorf("failed to parse logical switch port %q IP %q", portName, addresses[1])
	}
	mac, err := net.ParseMAC(addresses[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse logical switch port %q MAC %q: %v", portName, addresses[0], err)
	}
	return mac, ip, nil
}

// GetOVSPortMACAddress returns the MAC address of a given OVS port
func GetOVSPortMACAddress(portName string) (net.HardwareAddr, error) {
	macAddress, stderr, err := RunOVSVsctl("--if-exists", "get",
		"interface", portName, "mac_in_use")
	if err != nil {
		return nil, fmt.Errorf("Failed to get MAC address for %q, stderr: %q, error: %v",
			portName, stderr, err)
	}
	if macAddress == "" {
		return nil, fmt.Errorf("No mac_address found for %q", portName)
	}
	if runtime.GOOS == windowsOS && macAddress == "00:00:00:00:00:00" {
		macAddress, err = FetchIfMacWindows(portName)
		if err != nil {
			return nil, err
		}
	}

	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port %q MAC %q: %v", portName, macAddress, err)
	}

	return mac, nil
}
