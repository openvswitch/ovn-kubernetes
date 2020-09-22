module github.com/ovn-org/ovn-kubernetes/go-controller

go 1.13

require (
	github.com/Mellanox/sriovnet v0.0.0-20190516174650-73402dc8fcaa
	github.com/Microsoft/hcsshim v0.8.10-0.20200606013352-27a858bf1651
	github.com/bhendo/go-powershell v0.0.0-20190719160123-219e7fb4e41e
	github.com/cenk/hub v1.0.1 // indirect
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.8.6
	github.com/coreos/go-iptables v0.4.5
	github.com/ebay/go-ovn v0.1.0
	github.com/ebay/libovsdb v0.2.1-0.20200719163122-3332afaeb27c
	github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/golang/groupcache v0.0.0-20191027212112-611e8accdfc9 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/juju/errors v0.0.0-20200330140219-3fe23663418f // indirect
	github.com/juju/testing v0.0.0-20200608005635-e4eedbc6f7aa // indirect
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v0.0.0-20200626054723-37f83d1996bc
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	github.com/prometheus/client_golang v1.2.1
	github.com/satori/go.uuid v0.0.0-20181028125025-b2ce2384e17b // indirect
	github.com/spf13/afero v1.2.2
	github.com/stretchr/testify v1.4.0
	github.com/urfave/cli/v2 v2.2.0
	github.com/vishvananda/netlink v0.0.0-20200625175047-bca67dfc8220
	golang.org/x/sys v0.0.0-20200323222414-85ca7c5b95cd
	golang.org/x/text v0.3.3 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7
	gopkg.in/gcfg.v1 v1.2.3
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/warnings.v0 v0.1.2 // indirect
	k8s.io/api v0.18.6
	k8s.io/apiextensions-apiserver v0.18.6
	k8s.io/apimachinery v0.18.6
	k8s.io/client-go v0.18.6
	k8s.io/klog v1.0.0
	k8s.io/utils v0.0.0-20200324210504-a9aa75ae1b89
	sigs.k8s.io/controller-runtime v0.6.0
)

replace github.com/ebay/go-ovn v0.1.0 => github.com/ebay/go-ovn v0.1.1-0.20200810162212-30abed5fb968
