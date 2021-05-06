package testing

import (
	"fmt"

	goovn "github.com/ebay/go-ovn"
	"k8s.io/klog/v2"
)

// TODO: implement mock methods as we keep adding unit-tests
// Get logical router by name
func (mock *MockOVNClient) LRGet(lr string) ([]*goovn.LogicalRouter, error) {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()
	var lrCache MockObjectCacheByName
	var ok bool
	if lrCache, ok = mock.cache[LogicalRouterType]; !ok {
		klog.V(5).Infof("Cache doesn't have any object of type %s", LogicalRouterType)
		return nil, goovn.ErrorSchema
	}
	var lrouter interface{}
	if lrouter, ok = lrCache[lr]; !ok {
		return nil, goovn.ErrorNotFound
	}
	if lrRet, ok := lrouter.(*goovn.LogicalRouter); ok {
		return []*goovn.LogicalRouter{lrRet}, nil
	}
	return nil, fmt.Errorf("invalid object type assertion for %s", LogicalRouterType)

}

// Create logical router named lr
func (mock *MockOVNClient) LRAdd(lr string, external_ids map[string]string) (*goovn.OvnCommand, error) {
	klog.V(5).Infof("Adding  logical router %s", lr)
	extIdsMap := make(map[interface{}]interface{})
	for k, v := range external_ids {
		extIdsMap[k] = v
	}
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpAdd,
			table:   LogicalRouterType,
			objName: lr,
			obj:     &goovn.LogicalRouter{Name: lr, UUID: FakeUUID, ExternalID: extIdsMap},
		},
	}, nil
}

// Del lr and all its ports
func (mock *MockOVNClient) LRDel(lr string) (*goovn.OvnCommand, error) {
	klog.V(5).Infof("Deleting lr %s", lr)
	return &goovn.OvnCommand{
		Exe: &MockExecution{
			handler: mock,
			op:      OpDelete,
			table:   LogicalRouterType,
			objName: lr,
		},
	}, nil

}

// Get all logical routers
func (mock *MockOVNClient) LRList() ([]*goovn.LogicalRouter, error) {
	var lrCache MockObjectCacheByName
	var ok bool

	lrArray := []*goovn.LogicalRouter{}
	if lrCache, ok = mock.cache[LogicalRouterType]; !ok {
		klog.V(5).Infof("Cache doesn't have any object of type %s", LogicalRouterType)
		return nil, goovn.ErrorSchema
	}
	var lrEntry interface{}
	for _, lrEntry = range lrCache {
		lr, ok := lrEntry.(*goovn.LogicalRouter)
		if !ok {
			return nil, fmt.Errorf("invalid object type assertion for %s", LogicalRouterType)
		}
		lrArray = append(lrArray, lr)
	}
	return lrArray, nil
}

// Add LB to LR
func (mock *MockOVNClient) LRLBAdd(ls string, lb string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// Delete LB from LR
func (mock *MockOVNClient) LRLBDel(ls string, lb string) (*goovn.OvnCommand, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}

// List Load balancers for a LR
func (mock *MockOVNClient) LRLBList(ls string) ([]*goovn.LoadBalancer, error) {
	return nil, fmt.Errorf("method %s is not implemented yet", functionName())
}
