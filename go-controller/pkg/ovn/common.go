package ovn

import (
	"fmt"
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
