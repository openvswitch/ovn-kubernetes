package testing

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"

	goovn "github.com/ebay/go-ovn"
	aggErrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
)

const (
	LogicalSwitchType     string = "Logical_Switch"
	LogicalRouterType     string = "Logical_Router"
	LogicalSwitchPortType string = "Logical_Switch_Port"
	ChassisType           string = "Chassis"
	ACLType               string = "ACL"
	ChassisPrivateType    string = "Chassis_Private"
	LoadBalancerType      string = "Logical_Load_Balancer"
)

const (
	OpAdd    string = "Add"
	OpDelete string = "Delete"
	OpUpdate string = "Update"
)

// used to update fields for existing objects in mock cache
type UpdateCache struct {
	FieldType  string
	FieldValue interface{}
}

// object cache for mock ovn client
type MockObjectCacheByName map[string]interface{}

type MockExecution struct {
	handler   mockExecutionHandler
	op        string
	table     string
	objName   string
	obj       interface{}
	objUpdate UpdateCache
}

// mock ovn client for testing
type MockOVNClient struct {
	db string
	// cache holds ovn db rows by table name as the key
	cache map[string]MockObjectCacheByName
	// error injection
	// keys are of the form: Table:Name:FieldType
	errorCache map[string]error
	// Mutex synchronizing MockOVNClient's cache and errorCache
	mutex sync.Mutex
	// represents connected client
	connected bool
}

type mockExecutionHandler interface {
	ExecuteMockCommand(*MockExecution) error
}

var _ goovn.Client = &MockOVNClient{}

// MockOVNCommand implements OVNCommandInterface
var _ goovn.Execution = &MockExecution{}

// return a new mock client to operate on db
func NewMockOVNClient(db string) *MockOVNClient {
	mock := &MockOVNClient{
		db:         db,
		cache:      make(map[string]MockObjectCacheByName),
		errorCache: make(map[string]error),
		connected:  true,
	}
	mock.cache[LogicalSwitchPortType] = make(MockObjectCacheByName)
	mock.cache[ChassisType] = make(MockObjectCacheByName)
	mock.cache[LogicalSwitchType] = make(MockObjectCacheByName)
	mock.cache[ChassisPrivateType] = make(MockObjectCacheByName)
	mock.cache[LogicalRouterType] = make(MockObjectCacheByName)
	mock.cache[LoadBalancerType] = make(MockObjectCacheByName)
	return mock
}

func functionName() string {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return "???"
	}

	fn := runtime.FuncForPC(pc)
	return fn.Name()
}

// Client Interface Methods

// Close connection to OVN
func (mock *MockOVNClient) Close() error {
	mock.connected = false
	return nil
}

func (mock *MockOVNClient) ExecuteMockCommand(e *MockExecution) error {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()
	var (
		cache MockObjectCacheByName
		ok    bool
	)
	switch e.op {
	case OpAdd:
		if cache, ok = mock.cache[e.table]; !ok {
			cache = make(MockObjectCacheByName)
			mock.cache[e.table] = cache
		}
		if _, exists := cache[e.objName]; exists {
			return fmt.Errorf("object %s of type %s exists in cache", e.objName, e.table)
		}
		cache[e.objName] = e.obj
	case OpDelete:
		if cache, ok = mock.cache[e.table]; !ok {
			return fmt.Errorf("command to delete entry from %s when cache doesn't exist", e.table)
		}
		delete(cache, e.objName)
	case OpUpdate:
		if cache, ok = mock.cache[e.table]; !ok {
			return fmt.Errorf("command to update entry from %s when cache doesn't exist", e.table)
		}
		if err := mock.updateCache(e.table, e.objName, e.objUpdate, cache); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid command op: %s", e.op)
	}
	return nil
}

// Exec command, support multiple commands in one transaction.
// executes commands ensuring their temporal consistency
func (mock *MockOVNClient) Execute(cmds ...*goovn.OvnCommand) error {
	if !mock.connected {
		return syscall.ENOTCONN
	}

	errors := make([]error, 0, len(cmds))
	for _, cmd := range cmds {
		// go over each mock command and apply the
		// individual command's operations to the
		// cache
		exe, ok := cmd.Exe.(*MockExecution)
		if !ok {
			klog.Errorf("Type assertion failed for mock execution")
			panic("type assertion failed for mock execution")
		}
		if err := mock.ExecuteMockCommand(exe); err != nil {
			errors = append(errors, err)
		}
	}
	return aggErrors.NewAggregate(errors)
}

// updateCache takes an object by name objName and updates it's fields specified as
// update in the mock ovn client's db cache
// It also allows faking errors in command execution during updates
func (mock *MockOVNClient) updateCache(table string, objName string, update UpdateCache, mockCache MockObjectCacheByName) error {
	// first check if an error needs to be returned from a side-ways error cache lookup
	cachedErr := mock.retFromErrorCache(table, objName, update.FieldType)
	if cachedErr != nil {
		return cachedErr
	}
	switch table {
	case LogicalSwitchPortType:
		return mock.updateLSPCache(objName, update, mockCache)
	default:
		return fmt.Errorf("mock cache updates for %s are not implemented yet", table)
	}
}

// insert a fake error to the cache
func (mock *MockOVNClient) AddToErrorCache(table, name, fieldType string, err error) {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()
	mock.errorCache[fmt.Sprintf("%s:%s:%s", table, name, fieldType)] = err
}

// get fake error from cache
func (mock *MockOVNClient) retFromErrorCache(table, name, fieldType string) error {
	key := fmt.Sprintf("%s:%s:%s", table, name, fieldType)
	if val, ok := mock.errorCache[key]; ok {
		return val
	}
	return nil
}

// delete an instance of fake error from cache
func (mock *MockOVNClient) RemoveFromErrorCache(table, name, fieldType string) {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()
	key := fmt.Sprintf("%s:%s:%s", table, name, fieldType)
	delete(mock.errorCache, key)
}

func (e *MockExecution) Execute(cmds ...*goovn.OvnCommand) error {
	if len(cmds) > 1 {
		panic("Unexpected number of commands passed to MockExecution object")
	}
	if e != cmds[0].Exe {
		panic("Unexpected MockExecution mismatch")
	}
	return e.handler.ExecuteMockCommand(e)
}
