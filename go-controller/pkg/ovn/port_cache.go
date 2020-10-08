package ovn

import (
	"fmt"
	"net"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

type portCache struct {
	sync.RWMutex
	stopChan <-chan struct{}
	cache    map[string]*lpInfo
}

type lpInfo struct {
	name     string
	uuid     string
	nodeName string
	ips      []*net.IPNet
	mac      net.HardwareAddr
	// expires, if non-nil, indicates that this object is scheduled to be
	// removed at the given time
	expires time.Time
}

func newPortCache(stopChan <-chan struct{}) *portCache {
	return &portCache{
		stopChan: stopChan,
		cache:    make(map[string]*lpInfo),
	}
}

func (c *portCache) get(logicalPort string) (*lpInfo, error) {
	c.RLock()
	defer c.RUnlock()
	if info, ok := c.cache[logicalPort]; ok {
		return info, nil
	}
	return nil, fmt.Errorf("logical port %s not found in cache", logicalPort)
}

func (c *portCache) add(nodeName, logicalPort, uuid string, mac net.HardwareAddr, ips []*net.IPNet) *lpInfo {
	c.Lock()
	defer c.Unlock()
	portInfo := &lpInfo{
		nodeName: nodeName,
		name:     logicalPort,
		uuid:     uuid,
		ips:      ips,
		mac:      mac,
	}
	klog.V(5).Infof("port-cache(%s): added port %+v", logicalPort, portInfo)
	c.cache[logicalPort] = portInfo
	return portInfo
}

func (c *portCache) remove(logicalPort string) {
	c.Lock()
	defer c.Unlock()
	info, ok := c.cache[logicalPort]
	if !ok || !info.expires.IsZero() {
		klog.V(5).Infof("port-cache(%s): port not found in cache or already marked for removal", logicalPort)
		return
	}
	info.expires = time.Now().Add(time.Minute)
	klog.V(5).Infof("port-cache(%s): scheduling port for removal at %v", logicalPort, info.expires)

	// Removal must be deferred since, for example, NetworkPolicy pod handlers
	// may run after the main pod handler and look for items in the cache
	// on delete events.
	go func() {
		select {
		case <-time.After(time.Minute):
			c.Lock()
			defer c.Unlock()
			// remove the port info if its expiration time has elapsed.
			// This makes sure that we don't prematurely remove a port
			// that was deleted and re-added before the timer expires.
			if info, ok := c.cache[logicalPort]; ok && !info.expires.IsZero() {
				if time.Now().After(info.expires) {
					klog.V(5).Infof("port-cache(%s): removing port", logicalPort)
					delete(c.cache, logicalPort)
				}
			}
		case <-c.stopChan:
			break
		}
	}()
}
