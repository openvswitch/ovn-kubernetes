package testing

import (
	"fmt"

	goovn "github.com/ebay/go-ovn"
	"k8s.io/klog/v2"
)

const (
	LoadBalancer = "LoadBalancer"
)

// TODO: implement mock methods as we keep adding unit-tests
// Get logical switch by name
func (mock *MockOVNClient) LSGet(ls string) ([]*goovn.LogicalSwitch, error) {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()
	var lsCache MockObjectCacheByName
	var ok bool
	if lsCache, ok = mock.cache[LogicalSwitchType]; !ok {
		klog.V(5).Infof("Cache doesn't have any object of type %s", LogicalSwitchType)
		return nil, goovn.ErrorSchema
	}
	var lswitch interface{}
	if lswitch, ok = lsCache[ls]; !ok {
		return nil, goovn.ErrorNotFound
	}
	if lsRet, ok := lswitch.(*goovn.LogicalSwitch); ok {
		return []*goovn.LogicalSwitch{lsRet}, nil
	}
	return nil, fmt.Errorf("invalid object type assertion for %s", LogicalSwitchType)

}

// Create ls named SWITCH
func (mock *MockOVNClient) LSAdd(ls string) (*goovn.OvnCommand, error) {
	klog.V(5).Infof("Adding  switch %s", ls)
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpAdd,
			table:   LogicalSwitchType,
			objName: ls,
			obj:     &goovn.LogicalSwitch{Name: ls, UUID: FakeUUID},
		},
	}, nil
}

// Del ls and all its ports
func (mock *MockOVNClient) LSDel(ls string) (*goovn.OvnCommand, error) {
	klog.V(5).Infof("Deleting ls %s", ls)
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpDelete,
			table:   LogicalSwitchType,
			objName: ls,
		},
	}, nil

}

// Get all logical switches
func (mock *MockOVNClient) LSList() ([]*goovn.LogicalSwitch, error) {
	var lsCache MockObjectCacheByName
	var ok bool

	lsArray := []*goovn.LogicalSwitch{}
	if lsCache, ok = mock.cache[LogicalSwitchType]; !ok {
		klog.V(5).Infof("Cache doesn't have any object of type %s", LogicalSwitchType)
		return nil, goovn.ErrorSchema
	}
	var lsEntry interface{}
	for _, lsEntry = range lsCache {
		ls, ok := lsEntry.(*goovn.LogicalSwitch)
		if !ok {
			return nil, fmt.Errorf("invalid object type assertion for %s", LogicalSwitchType)
		}
		lsArray = append(lsArray, ls)
	}
	return lsArray, nil

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
