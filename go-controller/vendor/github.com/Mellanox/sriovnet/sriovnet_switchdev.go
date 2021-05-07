package sriovnet

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	utilfs "github.com/Mellanox/sriovnet/pkg/utils/filesystem"
)

const (
	netdevPhysSwitchID = "phys_switch_id"
	netdevPhysPortName = "phys_port_name"
)

type PortFlavour uint16

// Keep things consistent with netlink lib constants
// nolint:golint,stylecheck
const (
	PORT_FLAVOUR_PHYSICAL = iota
	_
	_
	PORT_FLAVOUR_PCI_PF
	PORT_FLAVOUR_PCI_VF
	PORT_FLAVOUR_UNKNOWN = 0xffff
)

// Regex that matches on the physical/upling port name
var physPortRepRegex = regexp.MustCompile(`^p(\d+)$`)

// Regex that matches on PF representor port name. These ports exists on Smart-NICs.
var pfPortRepRegex = regexp.MustCompile(`^(?:c\d+)?pf(\d+)$`)

// Regex that matches on VF representor port name
var vfPortRepRegex = regexp.MustCompile(`^(?:c\d+)?pf(\d+)vf(\d+)$`)

func parsePortName(physPortName string) (pfRepIndex, vfRepIndex int, err error) {
	pfRepIndex = -1
	vfRepIndex = -1

	// old kernel syntax of phys_port_name is vf index
	physPortName = strings.TrimSpace(physPortName)
	physPortNameInt, err := strconv.Atoi(physPortName)
	if err == nil {
		vfRepIndex = physPortNameInt
	} else {
		// new kernel syntax of phys_port_name [cZ]pfXVfY
		matches := vfPortRepRegex.FindStringSubmatch(physPortName)
		//nolint:gomnd
		if len(matches) != 3 {
			err = fmt.Errorf("failed to parse physPortName %s", physPortName)
		} else {
			pfRepIndex, err = strconv.Atoi(matches[1])
			if err == nil {
				vfRepIndex, err = strconv.Atoi(matches[2])
			}
		}
	}
	return pfRepIndex, vfRepIndex, err
}

func isSwitchdev(netdevice string) bool {
	swIDFile := filepath.Join(NetSysDir, netdevice, netdevPhysSwitchID)
	physSwitchID, err := utilfs.Fs.ReadFile(swIDFile)
	if err != nil {
		return false
	}
	if physSwitchID != nil && string(physSwitchID) != "" {
		return true
	}
	return false
}

// GetUplinkRepresentor gets a VF PCI address (e.g '0000:03:00.4') and
// returns the uplink represntor netdev name for that VF.
func GetUplinkRepresentor(vfPciAddress string) (string, error) {
	devicePath := filepath.Join(PciSysDir, vfPciAddress, "physfn", "net")
	devices, err := utilfs.Fs.ReadDir(devicePath)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %s: %v", vfPciAddress, err)
	}
	for _, device := range devices {
		if isSwitchdev(device.Name()) {
			// Try to get the phys port name, if not exists then fallback to check without it
			// phys_port_name should be in formant p<port-num> e.g p0,p1,p2 ...etc.
			if devicePhysPortName, err := getNetDevPhysPortName(device.Name()); err == nil {
				if !physPortRepRegex.MatchString(devicePhysPortName) {
					continue
				}
			}

			return device.Name(), nil
		}
	}
	return "", fmt.Errorf("uplink for %s not found", vfPciAddress)
}

func GetVfRepresentor(uplink string, vfIndex int) (string, error) {
	swIDFile := filepath.Join(NetSysDir, uplink, netdevPhysSwitchID)
	physSwitchID, err := utilfs.Fs.ReadFile(swIDFile)
	if err != nil || string(physSwitchID) == "" {
		return "", fmt.Errorf("cant get uplink %s switch id", uplink)
	}

	pfSubsystemPath := filepath.Join(NetSysDir, uplink, "subsystem")
	devices, err := utilfs.Fs.ReadDir(pfSubsystemPath)
	if err != nil {
		return "", err
	}
	for _, device := range devices {
		devicePath := filepath.Join(NetSysDir, device.Name())
		deviceSwIDFile := filepath.Join(devicePath, netdevPhysSwitchID)
		deviceSwID, err := utilfs.Fs.ReadFile(deviceSwIDFile)
		if err != nil || string(deviceSwID) != string(physSwitchID) {
			continue
		}
		physPortNameStr, err := getNetDevPhysPortName(device.Name())
		if err != nil {
			continue
		}
		pfRepIndex, vfRepIndex, _ := parsePortName(physPortNameStr)
		if pfRepIndex != -1 {
			pfPCIAddress, err := getPCIFromDeviceName(uplink)
			if err != nil {
				continue
			}
			PCIFuncAddress, err := strconv.Atoi(string((pfPCIAddress[len(pfPCIAddress)-1])))
			if pfRepIndex != PCIFuncAddress || err != nil {
				continue
			}
		}
		// At this point we're confident we have a representor.
		if vfRepIndex == vfIndex {
			return device.Name(), nil
		}
	}
	return "", fmt.Errorf("failed to find VF representor for uplink %s", uplink)
}

func getNetDevPhysPortName(netDev string) (string, error) {
	devicePortNameFile := filepath.Join(NetSysDir, netDev, netdevPhysPortName)
	physPortName, err := utilfs.Fs.ReadFile(devicePortNameFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(physPortName)), nil
}

// findNetdevWithPortNameCriteria returns netdev that matches a criteria function on the representor
// physical port name
func findNetdevWithPortNameCriteria(criteria func(string) bool) (string, error) {
	netdevs, err := utilfs.Fs.ReadDir(NetSysDir)
	if err != nil {
		return "", err
	}

	for _, netdev := range netdevs {
		// find matching VF representor
		netdevName := netdev.Name()
		portName, err := getNetDevPhysPortName(netdevName)
		if err != nil {
			continue
		}

		if criteria(portName) {
			return netdevName, nil
		}
	}
	return "", fmt.Errorf("no representor matched criteria")
}

// GetVfRepresentorSmartNIC returns VF representor on Smart-NIC for a host VF identified by pfID and vfIndex
func GetVfRepresentorSmartNIC(pfID, vfIndex string) (string, error) {
	// TODO(Adrianc): This method should change to get switchID and vfIndex as input, then common logic can
	// be shared with GetVfRepresentor, backward compatibility should be preserved when this happens.

	// pfID should be 0 or 1
	if pfID != "0" && pfID != "1" {
		return "", fmt.Errorf("unexpected pfID(%s). It should be 0 or 1", pfID)
	}

	// vfIndex should be an unsinged integer provided as a decimal number
	if _, err := strconv.ParseUint(vfIndex, 10, 32); err != nil {
		return "", fmt.Errorf("unexpected vfIndex(%s). It should be an unsigned decimal number", vfIndex)
	}

	// map for easy search of expected VF rep port name.
	// Note: no supoport for Multi-Chassis Smart-NICs
	expectedPhysPortNames := map[string]interface{}{
		fmt.Sprintf("pf%svf%s", pfID, vfIndex):   nil,
		fmt.Sprintf("c0pf%svf%s", pfID, vfIndex): nil,
	}

	netdev, err := findNetdevWithPortNameCriteria(func(portName string) bool {
		// if phys port name == pf<pfIndex>vf<vfIndex> or c0pf<pfIndex>vf<vfIndex> we have a match
		if _, ok := expectedPhysPortNames[portName]; ok {
			return true
		}
		return false
	})

	if err != nil {
		return "", fmt.Errorf("vf representor for pfID:%s, vfIndex:%s not found", pfID, vfIndex)
	}
	return netdev, nil
}

// GetRepresentorPortFlavour returns the representor port flavour
// Note: this method does not support old representor names used by old kernels
// e.g <vf_num> and will return PORT_FLAVOUR_UNKNOWN for such cases.
func GetRepresentorPortFlavour(netdev string) (PortFlavour, error) {
	if !isSwitchdev(netdev) {
		return PORT_FLAVOUR_UNKNOWN, fmt.Errorf("net device %s is does not represent an eswitch port", netdev)
	}
	// TODO(adrianc): switch implementation for devlink
	// read phy_port_name
	portName, err := getNetDevPhysPortName(netdev)
	if err != nil {
		return PORT_FLAVOUR_UNKNOWN, err
	}

	typeToRegex := map[PortFlavour]*regexp.Regexp{
		PORT_FLAVOUR_PHYSICAL: physPortRepRegex,
		PORT_FLAVOUR_PCI_PF:   pfPortRepRegex,
		PORT_FLAVOUR_PCI_VF:   vfPortRepRegex,
	}
	for flavour, regex := range typeToRegex {
		if regex.MatchString(portName) {
			return flavour, nil
		}
	}
	return PORT_FLAVOUR_UNKNOWN, nil
}

// parseSmartNICConfigFileOutput parses the config file content of a smart-nic
// representor port. The format of the file is a set of <key>:<value> pairs as follows:
//
// ```
//  MAC        : 0c:42:a1:c6:cf:7c
//  MaxTxRate  : 0
//  State      : Follow
// ```
func parseSmartNICConfigFileOutput(out string) map[string]string {
	configMap := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		entry := strings.SplitN(line, ":", 2)
		if len(entry) != 2 {
			// unexpected line format
			continue
		}
		configMap[strings.Trim(entry[0], " \t\n")] = strings.Trim(entry[1], " \t\n")
	}
	return configMap
}

// GetRepresentorMacAddress returns the MAC address of the port identified by the given representor netdev
// Note:
//    This method functionality is currently supported only for Smart-NICs.
//    Currently only netdev representors with PORT_FLAVOUR_PCI_PF are supported
func GetRepresentorMacAddress(netdev string) (net.HardwareAddr, error) {
	flavor, err := GetRepresentorPortFlavour(netdev)
	if err != nil {
		return nil, fmt.Errorf("unknown port flavour for netdev %s. %v", netdev, err)
	}
	if flavor == PORT_FLAVOUR_UNKNOWN {
		return nil, fmt.Errorf("unknown port flavour for netdev %s", netdev)
	}
	if flavor != PORT_FLAVOUR_PCI_PF {
		return nil, fmt.Errorf("unsupported port flavour for netdev %s", netdev)
	}
	// TODO(adrianc): switch implementation for devlink and generalize for non-smartNIC cases and other port flavours

	// read phy_port_name
	portName, err := getNetDevPhysPortName(netdev)
	if err != nil {
		return nil, err
	}
	// Extract port num
	portNum := pfPortRepRegex.FindStringSubmatch(portName)
	if len(portNum) < 2 {
		return nil, fmt.Errorf("failed to extract physical port number from port name %s of netdev %s",
			portName, netdev)
	}
	uplinkPhysPortName := "p" + portNum[1]
	// Find uplink netdev for that port
	uplinkNetdev, err := findNetdevWithPortNameCriteria(func(pname string) bool { return pname == uplinkPhysPortName })
	if err != nil {
		return nil, fmt.Errorf("failed to find uplink port for netdev %s. %v", netdev, err)
	}
	// get MAC address for netdev
	configPath := filepath.Join(NetSysDir, uplinkNetdev, "smart_nic", "pf", "config")
	out, err := utilfs.Fs.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read smart-nic config for %s. %v", netdev, err)
	}
	config := parseSmartNICConfigFileOutput(string(out))
	macStr, ok := config["MAC"]
	if !ok {
		return nil, fmt.Errorf("MAC address not found for %s", netdev)
	}
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC address \"%s\" for %s. %v", macStr, netdev, err)
	}
	return mac, nil
}
