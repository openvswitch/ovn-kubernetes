package testing

import (
	"fmt"
	goovn "github.com/ebay/go-ovn"
	"k8s.io/klog/v2"
)

const (
	PgLSPs     string = "PgLSPField"
	fakePgUUID string = "bf02f460-5058-4689-8fcb-d31a1e484ed2"
)

// Creates a new port group in the Port_Group table named "group" with optional "ports"  and "external_ids".
func (mock *MockOVNClient) PortGroupAdd(group string, ports []string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	if _, err := mock.PortGroupGet(group); err == nil {
		return nil, goovn.ErrorExist
	}

	ext_ids := make(map[interface{}]interface{})
	for k, v := range external_ids {
		ext_ids[k] = v
	}

	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpAdd,
			table:   PortGroupType,
			objName: group,
			obj: &goovn.PortGroup{
				UUID:       fakePgUUID,
				Name:       group,
				Ports:      ports,
				ACLs:       nil,
				ExternalID: ext_ids,
			},
		},
	}, nil
}

// Sets "ports" and/or "external_ids" on the port group named "group". It is an error if group does not exist.
func (mock *MockOVNClient) PortGroupUpdate(group string, ports []string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Add port to port group.
func (mock *MockOVNClient) PortGroupAddPort(group string, port string) (*goovn.OvnCommand, error) {
	var pg *goovn.PortGroup
	if pg, _ = mock.PortGroupGet(group); pg == nil {
		return nil, goovn.ErrorNotFound
	}

	// NOTE: to fully mock the real PortGroupAddPort, we should confirm that the port is not already in pg.Ports,
	// however, since the mock code uses the same UUID for all LSPs, that would happen every time we try to
	// add more than one port.  Therefore, this check is omitted.

	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpUpdate,
			table:   PortGroupType,
			objName: group,
			objUpdate: UpdateCache{
				FieldType:  PgLSPs,
				FieldValue: port,
				UpdateOp:   OpAdd,
			},
		},
	}, nil
}

// Remove port from port group.
func (mock *MockOVNClient) PortGroupRemovePort(group string, port string) (*goovn.OvnCommand, error) {
	var pg *goovn.PortGroup
	if pg, _ = mock.PortGroupGet(group); pg == nil {
		return nil, goovn.ErrorNotFound
	}

	if !listContains(pg.Ports, port) {
		return nil, goovn.ErrorNotFound
	}

	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpUpdate,
			table:   PortGroupType,
			objName: group,
			objUpdate: UpdateCache{
				FieldType:  PgLSPs,
				FieldValue: port,
				UpdateOp:   OpDelete,
			},
		},
	}, nil
}

// Deletes port group "group". It is an error if "group" does not exist.
func (mock *MockOVNClient) PortGroupDel(group string) (*goovn.OvnCommand, error) {
	if _, err := mock.PortGroupGet(group); err != nil {
		return nil, goovn.ErrorNotFound
	}

	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpDelete,
			table:   PortGroupType,
			objName: group,
			obj: &goovn.PortGroup{
				UUID:       fakePgUUID,
				Name:       group,
				Ports:      nil,
				ACLs:       nil,
				ExternalID: nil,
			},
		},
	}, nil
}

// Get PortGroup data structure if it exists
func (mock *MockOVNClient) PortGroupGet(group string) (*goovn.PortGroup, error) {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()

	var pgCache MockObjectCacheByName
	var ok bool
	if pgCache, ok = mock.cache[PortGroupType]; !ok {
		klog.V(5).Infof("Cache doesn't have any object of type %s", PortGroupType)
		return nil, goovn.ErrorSchema
	}
	var port interface{}
	if port, ok = pgCache[group]; !ok {
		return nil, goovn.ErrorNotFound
	}
	if pgRet, ok := port.(*goovn.PortGroup); ok {
		return pgRet, nil
	}
	return nil, fmt.Errorf("invalid object type assertion for %s", PortGroupType)
}

func listContains(list []string, element string) bool {
	for _, e := range list {
		if element == e {
			return true
		}
	}
	return false
}

// Remove element if it exists in list. otherwise, has no effect.
func removeElement(list []string, element string) []string {
	for i, e := range list {
		if element == e {
			list[i] = list[len(list)-1]
		}
	}
	return list[:len(list)-1]
}

// helper function that applies field updates for a given port group to the mock object cache
func (mock *MockOVNClient) updatePortGroupCache(pgName string, update UpdateCache, mockCache MockObjectCacheByName) error {
	var entry interface{}
	var pg *goovn.PortGroup
	var ok bool

	if entry, ok = mockCache[pgName]; !ok {
		return fmt.Errorf("error updating Port Group with name %s, Port Group doesn't exist", pgName)
	}

	if pg, ok = entry.(*goovn.PortGroup); !ok {
		panic("type assertion failed for Port Group cache entry")
	}

	switch update.FieldType {
	case PgLSPs:
		switch update.UpdateOp {
		case OpAdd:
			pg.Ports = append(pg.Ports, fmt.Sprintf("%v", update.FieldValue))
		case OpDelete:
			pg.Ports = removeElement(pg.Ports, fmt.Sprintf("%v", update.FieldValue))
		default:
			return fmt.Errorf("unrecognized update op: %s", update.UpdateOp)
		}
	default:
		return fmt.Errorf("unrecognized field type: %s", update.FieldType)
	}

	return nil
}
