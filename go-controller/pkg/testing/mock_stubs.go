package testing

import (
	"fmt"

	goovn "github.com/ebay/go-ovn"
	libovsdb "github.com/ebay/libovsdb"
)

// TODO: implement mock methods as we keep adding unit-tests
// Get logical switch by name
func (mock *MockOVNClient) LSGet(ls string) ([]*goovn.LogicalSwitch, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Create ls named SWITCH
func (mock *MockOVNClient) LSAdd(ls string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Del ls and all its ports
func (mock *MockOVNClient) LSDel(ls string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all logical switches
func (mock *MockOVNClient) LSList() ([]*goovn.LogicalSwitch, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add external_ids to logical switch
func (mock *MockOVNClient) LSExtIdsAdd(ls string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Del external_ids from logical_switch
func (mock *MockOVNClient) LSExtIdsDel(ls string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Link logical switch to router
func (mock *MockOVNClient) LinkSwitchToRouter(lsw, lsp, lr, lrp, lrpMac string, networks []string, externalIds map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LB to LSW
func (mock *MockOVNClient) LSLBAdd(ls string, lb string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LB from LSW
func (mock *MockOVNClient) LSLBDel(ls string, lb string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Load balancers for a LSW
func (mock *MockOVNClient) LSLBList(ls string) ([]*goovn.LoadBalancer, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add ACL to entity (PORT_GROUP or LOGICAL_SWITCH)
func (mock *MockOVNClient) ACLAddEntity(entityType goovn.EntityType, entity, direct, match, action string, priority int, external_ids map[string]string, logflag bool, meter string, severity string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Set (change) match criteria for ACL
func (mock *MockOVNClient) ACLSetMatchEntity(entityType goovn.EntityType, entity, direct, oldMatch, newMatch string, priority int) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Set (change) logging for ACL
func (mock *MockOVNClient) ACLSetLoggingEntity(entityType goovn.EntityType, entity, direct, match string, priority int, newLogflag bool, newMeter, newSeverity string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete acl from entity (PORT_GROUP or LOGICAL_SWITCH)
func (mock *MockOVNClient) ACLDelEntity(entityType goovn.EntityType, entity, direct, match string, priority int, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete acl
func (mock *MockOVNClient) ACLDel(ls, direct, match string, priority int, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all acl by entity
func (mock *MockOVNClient) ACLListEntity(entityType goovn.EntityType, entity string) ([]*goovn.ACL, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all acl by lswitch
func (mock *MockOVNClient) ACLList(ls string) ([]*goovn.ACL, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get AS
func (mock *MockOVNClient) ASGet(name string) (*goovn.AddressSet, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Update address set
func (mock *MockOVNClient) ASUpdate(name string, addrs []string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add addressset
func (mock *MockOVNClient) ASAdd(name string, addrs []string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete addressset
func (mock *MockOVNClient) ASDel(name string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all AS
func (mock *MockOVNClient) ASList() ([]*goovn.AddressSet, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get LR with given name
func (mock *MockOVNClient) LRGet(name string) ([]*goovn.LogicalRouter, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LR with given name
func (mock *MockOVNClient) LRAdd(name string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LR with given name
func (mock *MockOVNClient) LRDel(name string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get LRs
func (mock *MockOVNClient) LRList() ([]*goovn.LogicalRouter, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LRP with given name on given lr
func (mock *MockOVNClient) LRPAdd(lr string, lrp string, mac string, network []string, peer string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LRP with given name on given lr
func (mock *MockOVNClient) LRPDel(lr string, lrp string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all lrp by lr
func (mock *MockOVNClient) LRPList(lr string) ([]*goovn.LogicalRouterPort, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LRSR with given ip_prefix on given lr
func (mock *MockOVNClient) LRSRAdd(lr string, ip_prefix string, nexthop string, output_port *string, policy *string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LRSR with given ip_prefix, nexthop, outputPort and policy on given lr
func (mock *MockOVNClient) LRSRDel(lr string, prefix string, nexthop, outputPort, policy *string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LRSR by uuid given lr
func (mock *MockOVNClient) LRSRDelByUUID(lr, uuid string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get all LRSRs by lr
func (mock *MockOVNClient) LRSRList(lr string) ([]*goovn.LogicalRouterStaticRoute, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LB to LR
func (mock *MockOVNClient) LRLBAdd(lr string, lb string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LB from LR
func (mock *MockOVNClient) LRLBDel(lr string, lb string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Load balancers for a LR
func (mock *MockOVNClient) LRLBList(lr string) ([]*goovn.LoadBalancer, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get LB with given name
func (mock *MockOVNClient) LBGet(name string) ([]*goovn.LoadBalancer, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add LB
func (mock *MockOVNClient) LBAdd(name string, vipPort string, protocol string, addrs []string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LB with given name
func (mock *MockOVNClient) LBDel(name string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Update existing LB
func (mock *MockOVNClient) LBUpdate(name string, vipPort string, protocol string, addrs []string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Set selection fields for LB session affinity
func (mock *MockOVNClient) LBSetSelectionFields(name string, selectionFields string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add dhcp options for cidr and provided external_ids
func (mock *MockOVNClient) DHCPOptionsAdd(cidr string, options map[string]string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Set dhcp options and set external_ids for specific uuid
func (mock *MockOVNClient) DHCPOptionsSet(uuid string, options map[string]string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Del dhcp options via provided external_ids
func (mock *MockOVNClient) DHCPOptionsDel(uuid string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get single dhcp via provided uuid
func (mock *MockOVNClient) DHCPOptionsGet(uuid string) (*goovn.DHCPOptions, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List dhcp options
func (mock *MockOVNClient) DHCPOptionsList() ([]*goovn.DHCPOptions, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add qos rule
func (mock *MockOVNClient) QoSAdd(ls string, direction string, priority int, match string, action map[string]int, bandwidth map[string]int, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Del qos rule, to delete wildcard specify priority -1 and string options as ""
func (mock *MockOVNClient) QoSDel(ls string, direction string, priority int, match string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get qos rules by logical switch
func (mock *MockOVNClient) QoSList(ls string) ([]*goovn.QoS, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

//Add NAT to Logical Router
func (mock *MockOVNClient) LRNATAdd(lr string, ntype string, externalIp string, logicalIp string, external_ids map[string]string, logicalPortAndExternalMac ...string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

//Del NAT from Logical Router
func (mock *MockOVNClient) LRNATDel(lr string, ntype string, ip ...string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get NAT List by Logical Router
func (mock *MockOVNClient) LRNATList(lr string) ([]*goovn.NAT, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add Meter with a Meter Band
func (mock *MockOVNClient) MeterAdd(name, action string, rate int, unit string, external_ids map[string]string, burst int) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Deletes meters
func (mock *MockOVNClient) MeterDel(name ...string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Meters
func (mock *MockOVNClient) MeterList() ([]*goovn.Meter, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Meter Bands
func (mock *MockOVNClient) MeterBandsList() ([]*goovn.MeterBand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add chassis with given name
func (mock *MockOVNClient) ChassisAdd(name string, hostname string, etype []string, ip string, external_ids map[string]string,
	transport_zones []string, vtep_lswitches []string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get encaps by chassis name
func (mock *MockOVNClient) EncapList(chname string) ([]*goovn.Encap, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Chassis rows in chassis_private table
func (mock *MockOVNClient) ChassisPrivateList() ([]*goovn.ChassisPrivate, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get Chassis row in chassis_private table by given name
func (mock *MockOVNClient) ChassisPrivateGet(chName string) ([]*goovn.ChassisPrivate, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Set NB_Global table options
func (mock *MockOVNClient) NBGlobalSetOptions(options map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get NB_Global table options
func (mock *MockOVNClient) NBGlobalGetOptions() (map[string]string, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Set SB_Global table options
func (mock *MockOVNClient) SBGlobalSetOptions(options map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get SB_Global table options
func (mock *MockOVNClient) SBGlobalGetOptions() (map[string]string, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get ovn-db schema
func (mock *MockOVNClient) GetSchema() libovsdb.DatabaseSchema {
	var dbSchema libovsdb.DatabaseSchema
	return dbSchema
}
