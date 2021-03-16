package ovn

import (
	"fmt"
	godebug "github.com/anfredette/go-debug"
	goovn "github.com/ebay/go-ovn"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"k8s.io/klog/v2"
)

// hash the provided input to make it a valid portGroup name.
func hashedPortGroup(s string) string {
	return util.HashForOVN(s)
}

func createPortGroup(ovnNBClient goovn.Client, name string, hashName string) (string, error) {
	klog.V(5).Infof("createPortGroup with %s", name)
	externalIds := map[string]string{"name": name}
	cmd, err := ovnNBClient.PortGroupAdd(hashName, nil, externalIds)
	if err == nil {
		if err = ovnNBClient.Execute(cmd); err != nil {
			return "", fmt.Errorf("execute error for add port group: %s, %v", name, err)
		}
	} else if err != goovn.ErrorExist {
		// Ignore goovn.ErrorExist to implement "--may-exist" behavior
		return "", fmt.Errorf("add error for port group: %s, %v", name, err)
	}

	pg, err := ovnNBClient.PortGroupGet(hashName)
	if err == nil {
		return pg.UUID, nil
	} else {
		return "", fmt.Errorf("failed to get port group UUID: %s, %v", name, err)
	}
}

func deletePortGroup(ovnNBClient goovn.Client, hashName string) error {
	klog.V(5).Infof("deletePortGroup %s", hashName)
	cmd, err := ovnNBClient.PortGroupDel(hashName)
	if err == nil {
		if err = ovnNBClient.Execute(cmd); err != nil {
			return fmt.Errorf("execute error for delete port group: %s, %v", hashName, err)
		}
	} else if err != goovn.ErrorNotFound {
		// Ignore goovn.ErrorNotFound to implement "--if-exist" behavior
		return fmt.Errorf("delete error for port group: %s, %v", hashName, err)
	}
	return nil
}

func stringSliceMembership(slice []string, key string) bool {
	for _, val := range slice {
		if val == key {
			return true
		}
	}
	return false
}

func addACL(ovnNBClient goovn.Client, entityType goovn.EntityType, entityName, direction, match, action string, priority int,
	external_ids map[string]string, logflag bool, meter, severity string) error {
	klog.Infof("ANF: %s: %s, %s, %s, %s, %s, %d, %+v, %t, %s, %s,", godebug.Location(), entityType, entityName, direction, match, action, priority, external_ids, logflag, meter, severity)

	cmd, err := ovnNBClient.ACLAddEntity(entityType, entityName, direction, match, action, priority, external_ids, logflag, meter, severity)
	if err == nil {
		if err = ovnNBClient.Execute(cmd); err != nil {
			klog.Infof("ANF: ERROR: %s, (%+v)", godebug.Location(), err)
			return fmt.Errorf("acl add execute error for %s %s, %s, %s, %d, %+v (%v)", entityType, entityName, direction, match, priority, external_ids, err)
		}
		// Ignore goovn.ErrorExist to implement "--may-exist" behavior
	} else if err != goovn.ErrorExist {
		klog.Infof("ANF: ERROR: %s, (%+v)", godebug.Location(), err)
		return fmt.Errorf("acl add error for %s %s, %s, %s, %d, %+v (%v)", entityType, entityName, direction, match, priority, external_ids, err)
	}

	return nil
}

// 	ACLSetMatchEntity(entityType EntityType, entity, direct, oldMatch, newMatch string, priority int)
func modifyACLMatch(ovnNBClient goovn.Client, entityType goovn.EntityType, entityName, direct, oldMatch, newMatch string, priority int) error {
	klog.Infof("ANF: %s: %s %s, %s, %s, %s, %d", godebug.Location(), entityType, entityName, direct, oldMatch, newMatch, priority)

	cmd, err := ovnNBClient.ACLSetMatchEntity(entityType, entityName, direct, oldMatch, newMatch, priority)
	if err == nil {
		if err = ovnNBClient.Execute(cmd); err != nil {
			klog.Infof("ANF: ERROR: %s, (%+v)", godebug.Location(), err)
			return fmt.Errorf("modify ACL match execute error for %s %s, %s, %s, %s, %d, (%v)", entityType, entityName, direct, oldMatch, newMatch, priority, err)
		}
		// Ignore goovn.ErrorExist to implement "--may-exist" behavior
	} else if err != goovn.ErrorExist {
		klog.Infof("ANF: ERROR: %s, (%+v)", godebug.Location(), err)
		return fmt.Errorf("modify ACL match error for %s %s, %s, %s, %s, %d, (%v)", entityType, entityName, direct, oldMatch, newMatch, priority, err)
	}

	return nil
}

/*
func deleteACL(ovnNBClient goovn.Client, entityType goovn.EntityType, entityName, direction, match string, priority int, external_ids map[string]string) error {
	klog.Infof("ANF: %s", godebug.Location())

	// entityType, entity, direct, match, priority, external_ids
	cmd, err := ovnNBClient.ACLDelEntity(entityType, entityName, direction, match, priority, external_ids)
	if err == nil {
		if err = ovnNBClient.Execute(cmd); err != nil {
			klog.Infof("ANF: ERROR: %s, (%+v)", godebug.Location(), err)
			return fmt.Errorf("acl delete execute error for %s %s, %s, %s, %d, %+v (%v)", entityType, entityName, direction, match, priority, external_ids, err)
		}
		// Ignore goovn.ErrorExist to implement "--may-exist" behavior
	} else if err != goovn.ErrorExist {
		klog.Infof("ANF: ERROR: %s, (%+v)", godebug.Location(), err)
		return fmt.Errorf("acl delete error for %s %s, %s, %s, %d, %+v (%v)", entityType, entityName, direction, match, priority, external_ids, err)
	}

	return nil
}
*/
