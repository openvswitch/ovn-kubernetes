package testing

import (
	"fmt"
	goovn "github.com/ebay/go-ovn"
	"k8s.io/klog/v2"
	"strings"
)

const (
	LoadBalancerVIPs            = "vips"
	LoadBalancerProtocol        = "protocol"
	LoadBalancerSelectionFields = "selectionFields"
)

// Get LB with given name
func (mock *MockOVNClient) LBGet(lb string) ([]*goovn.LoadBalancer, error) {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()
	var lbCache MockObjectCacheByName
	var ok bool
	if lbCache, ok = mock.cache[LoadBalancerType]; !ok {
		klog.V(5).Infof("Cache doesn't have any object of type %s", LoadBalancerType)
		return nil, goovn.ErrorSchema
	}
	var port interface{}
	if port, ok = lbCache[lb]; !ok {
		return nil, goovn.ErrorNotFound
	}
	if lbRet, ok := port.(*goovn.LoadBalancer); ok {
		return []*goovn.LoadBalancer{lbRet}, nil
	}
	return nil, fmt.Errorf("invalid object type assertion for %s", LoadBalancerType)
}

// Add LB
func (mock *MockOVNClient) LBAdd(lb string, vipPort string, protocol string, addrs []string) (*goovn.OvnCommand, error) {
	klog.V(5).Infof("Adding load balancer %s", lb)
	vipMap := make(map[interface{}]interface{})
	// prepare vips map

	vipMap[vipPort] = strings.Join(addrs, ",")
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpAdd,
			table:   LoadBalancerType,
			objName: lb,
			obj:     &goovn.LoadBalancer{Name: lb, UUID: FakeUUID, VIPs: vipMap, Protocol: protocol},
		},
	}, nil
}

// Delete LB with given name
func (mock *MockOVNClient) LBDel(lb string) (*goovn.OvnCommand, error) {
	klog.V(5).Infof("Deleting lb %s", lb)
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpDelete,
			table:   LoadBalancerType,
			objName: lb,
		},
	}, nil
}

// Update existing LB
func (mock *MockOVNClient) LBUpdate(lb string, vipPort string, protocol string, addrs []string) (*goovn.OvnCommand, error) {
	fieldVal := vipPort + "--" + strings.Join(addrs, ",") + ";" + protocol
	fieldType := "vips;protocol"
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpUpdate,
			table:   LoadBalancerType,
			objName: lb,
			objUpdate: UpdateCache{
				FieldType:  fieldType,
				FieldValue: fieldVal,
			},
		},
	}, nil

}

// Set selection fields for LB session affinity
func (mock *MockOVNClient) LBSetSelectionFields(lb string, selectionFields string) (*goovn.OvnCommand, error) {
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpUpdate,
			table:   LoadBalancerType,
			objName: lb,
			objUpdate: UpdateCache{
				FieldType:  LoadBalancerSelectionFields,
				FieldValue: selectionFields,
			},
		},
	}, nil
}

// helper function that applies field updates for a given lb to the mock object cache
func (mock *MockOVNClient) updateLBCache(lbName string, update UpdateCache, mockCache MockObjectCacheByName) error {
	var entry interface{}
	var lb *goovn.LoadBalancer
	var ok bool
	var fieldValueStr string
	if entry, ok = mockCache[lbName]; !ok {
		return fmt.Errorf("error updating LB with name %s, LB doesn't exist", lbName)
	}

	if lb, ok = entry.(*goovn.LoadBalancer); !ok {
		panic("type assertion failed for LB cache entry")
	}

	if fieldValueStr, ok = update.FieldValue.(string); !ok {
		return fmt.Errorf("type assertion failed for LB field: %s", update.FieldType)
	}

	fieldValues := strings.Split(fieldValueStr, ";")
	fieldNames := strings.Split(update.FieldType, ";")

	for idx, entry := range fieldNames {
		switch entry {
		case LoadBalancerVIPs:
			vipFields := strings.Split(fieldValues[idx], "--")
			vipPort := vipFields[0]
			addrs := vipFields[1]
			lb.VIPs[vipPort] = addrs
			klog.V(5).Infof("Setting addresses %s for vipPort %s on LB %s", addrs, vipPort, lbName)
		case LoadBalancerProtocol:
			protocol := fieldValues[idx]
			lb.Protocol = protocol
			klog.V(5).Infof("Setting Protocol to  %s on LB %s", protocol, lbName)
		case LoadBalancerSelectionFields:
			selectionFields := fieldValues[idx]
			lb.SelectionFields = selectionFields
			klog.V(5).Infof("Setting selectionFields to %s on LB %s", selectionFields, lbName)
		default:
			return fmt.Errorf("unrecognized field type: %s", update.FieldType)

		}
	}

	return nil
}
