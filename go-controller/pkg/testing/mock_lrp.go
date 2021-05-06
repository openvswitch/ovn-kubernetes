package testing

import (
	"fmt"

	goovn "github.com/ebay/go-ovn"
	"k8s.io/klog/v2"
)

// Add logical port to router
func (mock *MockOVNClient) LRPAdd(lr string, lrp string, mac string, network []string, peer string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	klog.V(5).Infof("Adding lrp %s to router %s", lrp, lr)
	extIdsMap := make(map[interface{}]interface{})
	for k, v := range external_ids {
		extIdsMap[k] = v
	}
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpAdd,
			table:   LogicalRouterPortType,
			objName: lrp,
			obj:     &goovn.LogicalRouterPort{Name: lrp, UUID: FakeUUID, MAC: mac, Networks: network, Peer: peer, ExternalID: extIdsMap},
		},
	}, nil
}

// Delete lrp from its attached router
func (mock *MockOVNClient) LRPDel(lr string, lrp string) (*goovn.OvnCommand, error) {
	klog.V(5).Infof("Deleting lrp %s", lrp)
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpDelete,
			table:   LogicalRouterPortType,
			objName: lrp,
		},
	}, nil
}

// Get all lrport by lrouter
func (mock *MockOVNClient) LRPList(lr string) ([]*goovn.LogicalRouterPort, error) {
	klog.V(5).Infof("LRPList called for lr: %s", lr)
	var lrpCache MockObjectCacheByName
	var ok bool

	lrpArray := []*goovn.LogicalRouterPort{}
	if lrpCache, ok = mock.cache[LogicalRouterPortType]; !ok {
		klog.V(5).Infof("Cache doesn't have any object of type %s", LogicalRouterPortType)
		return nil, goovn.ErrorSchema
	}
	var lrpEntry interface{}
	for _, lrpEntry = range lrpCache {
		lrp, ok := lrpEntry.(*goovn.LogicalRouterPort)
		if !ok {
			return nil, fmt.Errorf("invalid object type assertion for %s", LogicalRouterPortType)
		}
		lrpArray = append(lrpArray, lrp)
	}
	return lrpArray, nil
}
