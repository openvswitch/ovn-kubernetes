package testing

import (
	"fmt"

	goovn "github.com/ebay/go-ovn"
	libovsdb "github.com/ebay/libovsdb"
)

// Add ACL to entity (PORT_GROUP or LOGICAL_SWITCH)
func (mock *MockOVNClient) ACLAddEntity(entityType goovn.EntityType, entity, direct, match, action string, priority int, external_ids map[string]string, logflag bool, meter string, severity string) (*goovn.OvnCommand, error) {
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

// Creates a new port group in the Port_Group table named "group" with optional "ports"  and "external_ids".
func (mock *MockOVNClient) PortGroupAdd(group string, ports []string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Sets "ports" and/or "external_ids" on the port group named "group". It is an error if group does not exist.
func (mock *MockOVNClient) PortGroupUpdate(group string, ports []string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add port to port group.
func (mock *MockOVNClient) PortGroupAddPort(group string, port string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Remove port from port group.
func (mock *MockOVNClient) PortGroupRemovePort(group string, port string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Deletes port group "group". It is an error if "group" does not exist.
func (mock *MockOVNClient) PortGroupDel(group string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get PortGroup data structure if it exists
func (mock *MockOVNClient) PortGroupGet(group string) (*goovn.PortGroup, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Get ovn-db schema
func (mock *MockOVNClient) GetSchema() libovsdb.DatabaseSchema {
	var dbSchema libovsdb.DatabaseSchema
	return dbSchema
}
