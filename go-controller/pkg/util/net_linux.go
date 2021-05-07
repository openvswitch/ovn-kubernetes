// +build linux

package util

import (
	"bytes"
	"fmt"
	"net"
	"os"

	kapi "k8s.io/api/core/v1"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	utilnet "k8s.io/utils/net"
)

type NetLinkOps interface {
	LinkList() ([]netlink.Link, error)
	LinkByName(ifaceName string) (netlink.Link, error)
	LinkSetDown(link netlink.Link) error
	LinkDelete(link netlink.Link) error
	LinkSetName(link netlink.Link, newName string) error
	LinkSetUp(link netlink.Link) error
	LinkSetNsFd(link netlink.Link, fd int) error
	LinkSetHardwareAddr(link netlink.Link, hwaddr net.HardwareAddr) error
	LinkSetMTU(link netlink.Link, mtu int) error
	LinkSetTxQLen(link netlink.Link, qlen int) error
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	AddrDel(link netlink.Link, addr *netlink.Addr) error
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	RouteDel(route *netlink.Route) error
	RouteAdd(route *netlink.Route) error
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	NeighAdd(neigh *netlink.Neigh) error
	NeighList(linkIndex, family int) ([]netlink.Neigh, error)
	ConntrackDeleteFilter(table netlink.ConntrackTableType, family netlink.InetFamily, filter netlink.CustomConntrackFilter) (uint, error)
}

type defaultNetLinkOps struct {
}

var netLinkOps NetLinkOps = &defaultNetLinkOps{}

// SetNetLinkOpMockInst method would be used by unit tests in other packages
func SetNetLinkOpMockInst(mockInst NetLinkOps) {
	netLinkOps = mockInst
}

// GetNetLinkOps will be invoked by functions in other packages that would need access to the netlink library methods.
func GetNetLinkOps() NetLinkOps {
	return netLinkOps
}

func (defaultNetLinkOps) LinkList() ([]netlink.Link, error) {
	return netlink.LinkList()
}

func (defaultNetLinkOps) LinkByName(ifaceName string) (netlink.Link, error) {
	return netlink.LinkByName(ifaceName)
}

func (defaultNetLinkOps) LinkSetDown(link netlink.Link) error {
	return netlink.LinkSetDown(link)
}

func (defaultNetLinkOps) LinkDelete(link netlink.Link) error {
	return netlink.LinkDel(link)
}

func (defaultNetLinkOps) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (defaultNetLinkOps) LinkSetName(link netlink.Link, newName string) error {
	return netlink.LinkSetName(link, newName)
}

func (defaultNetLinkOps) LinkSetNsFd(link netlink.Link, fd int) error {
	return netlink.LinkSetNsFd(link, fd)
}

func (defaultNetLinkOps) LinkSetHardwareAddr(link netlink.Link, hwaddr net.HardwareAddr) error {
	return netlink.LinkSetHardwareAddr(link, hwaddr)
}

func (defaultNetLinkOps) LinkSetMTU(link netlink.Link, mtu int) error {
	return netlink.LinkSetMTU(link, mtu)
}

func (defaultNetLinkOps) LinkSetTxQLen(link netlink.Link, qlen int) error {
	return netlink.LinkSetTxQLen(link, qlen)
}

func (defaultNetLinkOps) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return netlink.AddrList(link, family)
}

func (defaultNetLinkOps) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrDel(link, addr)
}

func (defaultNetLinkOps) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrAdd(link, addr)
}

func (defaultNetLinkOps) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return netlink.RouteList(link, family)
}

func (defaultNetLinkOps) RouteDel(route *netlink.Route) error {
	return netlink.RouteDel(route)
}

func (defaultNetLinkOps) RouteAdd(route *netlink.Route) error {
	return netlink.RouteAdd(route)
}

func (defaultNetLinkOps) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, filter, filterMask)
}

func (defaultNetLinkOps) NeighAdd(neigh *netlink.Neigh) error {
	return netlink.NeighAdd(neigh)
}

func (defaultNetLinkOps) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return netlink.NeighList(linkIndex, family)
}

func (defaultNetLinkOps) ConntrackDeleteFilter(table netlink.ConntrackTableType, family netlink.InetFamily, filter netlink.CustomConntrackFilter) (uint, error) {
	return netlink.ConntrackDeleteFilter(table, family, filter)
}

func getFamily(ip net.IP) int {
	if utilnet.IsIPv6(ip) {
		return netlink.FAMILY_V6
	} else {
		return netlink.FAMILY_V4
	}
}

// LinkSetUp returns the netlink device with its state marked up
func LinkSetUp(interfaceName string) (netlink.Link, error) {
	link, err := netLinkOps.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup link %s: %v", interfaceName, err)
	}
	err = netLinkOps.LinkSetUp(link)
	if err != nil {
		return nil, fmt.Errorf("failed to set the link %s up: %v", interfaceName, err)
	}
	return link, nil
}

// LinkDelete removes an interface
func LinkDelete(interfaceName string) error {
	link, err := netLinkOps.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to lookup link %s: %v", interfaceName, err)
	}
	err = netLinkOps.LinkDelete(link)
	if err != nil {
		return fmt.Errorf("failed to remove link %s, error: %v", interfaceName, err)
	}
	return nil
}

// LinkAddrFlush flushes all the addresses on the given link, except IPv6 link-local addresses
func LinkAddrFlush(link netlink.Link) error {
	addrs, err := netLinkOps.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list addresses for the link %s: %v", link.Attrs().Name, err)
	}
	for _, addr := range addrs {
		if utilnet.IsIPv6(addr.IP) && addr.IP.IsLinkLocalUnicast() {
			continue
		}
		err = netLinkOps.AddrDel(link, &addr)
		if err != nil {
			return fmt.Errorf("failed to delete address %s on link %s: %v",
				addr.IP.String(), link.Attrs().Name, err)
		}
	}
	return nil
}

// LinkAddrExist returns true if the given address is present on the link
func LinkAddrExist(link netlink.Link, address *net.IPNet) (bool, error) {
	addrs, err := netLinkOps.AddrList(link, getFamily(address.IP))
	if err != nil {
		return false, fmt.Errorf("failed to list addresses for the link %s: %v",
			link.Attrs().Name, err)
	}
	for _, addr := range addrs {
		if addr.IPNet.String() == address.String() {
			return true, nil
		}
	}
	return false, nil
}

// LinkAddrAdd removes existing addresses on the link and adds the new address
func LinkAddrAdd(link netlink.Link, address *net.IPNet) error {
	err := netLinkOps.AddrAdd(link, &netlink.Addr{IPNet: address})
	if err != nil {
		return fmt.Errorf("failed to add address %s on link %s: %v", address, link.Attrs().Name, err)
	}
	return nil
}

// LinkRoutesDel deletes all the routes for the given subnets via the link
// if subnets is empty, then all routes will be removed for a link
func LinkRoutesDel(link netlink.Link, subnets []*net.IPNet) error {
	routes, err := netLinkOps.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get all the routes for link %s: %v",
			link.Attrs().Name, err)
	}
	for _, route := range routes {
		if len(subnets) == 0 {
			err = netLinkOps.RouteDel(&route)
			if err != nil {
				return fmt.Errorf("failed to delete route '%s via %s' for link %s : %v\n",
					route.Dst.String(), route.Gw.String(), link.Attrs().Name, err)
			}
			continue
		}
		for _, subnet := range subnets {
			if route.Dst.String() == subnet.String() {
				err = netLinkOps.RouteDel(&route)
				if err != nil {
					return fmt.Errorf("failed to delete route '%s via %s' for link %s : %v\n",
						route.Dst.String(), route.Gw.String(), link.Attrs().Name, err)
				}
				break
			}
		}
	}
	return nil
}

// LinkRoutesAdd adds a new route for given subnets through the gwIPstr
func LinkRoutesAdd(link netlink.Link, gwIP net.IP, subnets []*net.IPNet) error {
	for _, subnet := range subnets {
		route := &netlink.Route{
			Dst:       subnet,
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Gw:        gwIP,
		}
		err := netLinkOps.RouteAdd(route)
		if err != nil {
			if os.IsExist(err) {
				return err
			}
			return fmt.Errorf("failed to add route for subnet %s via gateway %s: %v",
				subnet.String(), gwIP.String(), err)
		}
	}
	return nil
}

// LinkRouteExists checks for existence of routes for the given subnet through gwIPStr
func LinkRouteExists(link netlink.Link, gwIP net.IP, subnet *net.IPNet) (bool, error) {
	routeFilter := &netlink.Route{Dst: subnet, LinkIndex: link.Attrs().Index}
	filterMask := netlink.RT_FILTER_DST | netlink.RT_FILTER_OIF
	routes, err := netLinkOps.RouteListFiltered(getFamily(gwIP), routeFilter, filterMask)
	if err != nil {
		return false, fmt.Errorf("failed to get routes for subnet %s", subnet.String())
	}
	for _, route := range routes {
		if route.Gw.Equal(gwIP) {
			return true, nil
		}
	}
	return false, nil
}

// LinkNeighAdd adds MAC/IP bindings for the given link
func LinkNeighAdd(link netlink.Link, neighIP net.IP, neighMAC net.HardwareAddr) error {
	neigh := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       getFamily(neighIP),
		State:        netlink.NUD_PERMANENT,
		IP:           neighIP,
		HardwareAddr: neighMAC,
	}
	err := netLinkOps.NeighAdd(neigh)
	if err != nil {
		return fmt.Errorf("failed to add neighbour entry %+v: %v", neigh, err)
	}
	return nil
}

// LinkNeighExists checks to see if the given MAC/IP bindings exists
func LinkNeighExists(link netlink.Link, neighIP net.IP, neighMAC net.HardwareAddr) (bool, error) {
	neighs, err := netLinkOps.NeighList(link.Attrs().Index, getFamily(neighIP))
	if err != nil {
		return false, fmt.Errorf("failed to get the list of neighbour entries for link %s",
			link.Attrs().Name)
	}

	for _, neigh := range neighs {
		if neigh.IP.Equal(neighIP) {
			if bytes.Equal(neigh.HardwareAddr, neighMAC) &&
				(neigh.State&netlink.NUD_PERMANENT) == netlink.NUD_PERMANENT {
				return true, nil
			}
		}
	}
	return false, nil
}

func DeleteConntrack(ip string, port int32, protocol kapi.Protocol) error {
	ipAddress := net.ParseIP(ip)
	if ipAddress == nil {
		return fmt.Errorf("value %q passed to DeleteConntrack is not an IP address", ipAddress)
	}

	filter := &netlink.ConntrackFilter{}
	if protocol == kapi.ProtocolUDP {
		// 17 = UDP protocol
		if err := filter.AddProtocol(17); err != nil {
			return fmt.Errorf("could not add Protocol UDP to conntrack filter %v", err)
		}
	} else if protocol == kapi.ProtocolSCTP {
		// 132 = SCTP protocol
		if err := filter.AddProtocol(132); err != nil {
			return fmt.Errorf("could not add Protocol SCTP to conntrack filter %v", err)
		}
	}
	if port > 0 {
		if err := filter.AddPort(netlink.ConntrackOrigDstPort, uint16(port)); err != nil {
			return fmt.Errorf("could not add port %d to conntrack filter: %v", port, err)
		}
	}
	if err := filter.AddIP(netlink.ConntrackReplyAnyIP, ipAddress); err != nil {
		return fmt.Errorf("could not add IP: %s to conntrack filter: %v", ipAddress, err)
	}
	if ipAddress.To4() != nil {
		if _, err := netLinkOps.ConntrackDeleteFilter(netlink.ConntrackTable, netlink.FAMILY_V4, filter); err != nil {
			return err
		}
	} else {
		if _, err := netLinkOps.ConntrackDeleteFilter(netlink.ConntrackTable, netlink.FAMILY_V6, filter); err != nil {
			return err
		}
	}
	return nil
}

// GetNetworkInterfaceIPs returns the IP addresses for the network interface 'iface'.
func GetNetworkInterfaceIPs(iface string) ([]*net.IPNet, error) {
	link, err := netLinkOps.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup link %s: %v", iface, err)
	}

	addrs, err := netLinkOps.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses for %q: %v", iface, err)
	}

	var ips []*net.IPNet
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() {
			continue
		}
		// Ignore addresses marked as secondary or deprecated since they may
		// disappear. (In bare metal clusters using MetalLB or similar, these
		// flags are used to mark load balancer IPs that aren't permanently owned
		// by the node).
		if (addr.Flags & (unix.IFA_F_SECONDARY | unix.IFA_F_DEPRECATED)) != 0 {
			continue
		}
		ips = append(ips, addr.IPNet)
	}
	return ips, nil
}
