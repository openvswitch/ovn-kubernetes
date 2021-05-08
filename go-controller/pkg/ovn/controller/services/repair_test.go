package services

import (
	"testing"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	tcpLBUUID        string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
	udpLBUUID        string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
	sctpLBUUID       string = "0514c521-a120-4756-aec6-883fe5db7139"
	grTcpLBUUID      string = "001c2ec6-2f32-11eb-9bc2-a8a1590cda29"
	grUdpLBUUID      string = "05c55ae6-2f32-11eb-822e-a8a1590cda29"
	grSctpLBUUID     string = "0ac92874-2f32-11eb-8ca0-a8a1590cda29"
	workerTCPLBUUID  string = "2095292c-adb4-11eb-8529-0242ac130003"
	workerUDPLBUUID  string = "2b662964-adb4-11eb-8529-0242ac130003"
	workerSCTPLBUUID string = "50738e40-adb4-11eb-8529-0242ac130003"
	idlingTCPLB      string = "a64d5efe-adb4-11eb-8529-0242ac130003"
	idlingUDPLB      string = "bd58fa04-adb4-11eb-8529-0242ac130003"
	idlingSCTPLB     string = "c90b1940-adb4-11eb-8529-0242ac130003"
)

func newServiceInformer() coreinformers.ServiceInformer {
	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	return informerFactory.Core().V1().Services()
}

func TestRepair_Empty(t *testing.T) {
	serviceInformer := newServiceInformer()
	r := &Repair{
		interval:      0,
		serviceLister: serviceInformer.Lister(),
	}
	// Expected OVN commands
	fexec := ovntest.NewFakeExec()
	initializeClusterIPLBs(fexec)
	// OVN is empty
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + sctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grSctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerSCTPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingSCTPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + tcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grTcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerTCPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingTCPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + udpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grUdpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerUDPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingUDPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --columns=_uuid --format=csv --data=bare --no-headings find acl action=reject",
		Output: "",
	})

	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	if err := r.runOnce(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestRepair_OVNStaleData(t *testing.T) {
	serviceInformer := newServiceInformer()
	r := &Repair{
		interval:      0,
		serviceLister: serviceInformer.Lister(),
	}
	fexec := ovntest.NewLooseCompareFakeExec()
	initializeClusterIPLBs(fexec)
	// There are remaining OVN LB that doesn't exist in Kubernetes
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + sctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grSctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerSCTPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingSCTPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + tcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grTcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerTCPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingTCPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + udpLBUUID + " vips",
		Output: `{"10.96.0.10:53"="10.244.2.3:53,10.244.2.5:53", "10.96.0.10:9153"="10.244.2.3:9153,10.244.2.5:9153", "10.96.0.1:443"="172.19.0.3:6443"}`,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grUdpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerUDPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingUDPLB + " vips",
		Output: "",
	})
	// The repair loop must delete the remaining entries in OVN
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer " + udpLBUUID + " vips \"10.96.0.10:53\"",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer " + udpLBUUID + " vips \"10.96.0.10:9153\"",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer " + udpLBUUID + " vips \"10.96.0.1:443\"",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --columns=_uuid --format=csv --data=bare --no-headings find acl action=reject",
		Output: "",
	})

	// The repair loop must delete them
	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	if err := r.runOnce(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestRepair_OVNSynced(t *testing.T) {
	// Initialize informer cache
	serviceInformer := newServiceInformer()
	serviceStore := serviceInformer.Informer().GetStore()
	serviceStore.Add(createService("svc1", "10.96.0.10", 80))
	serviceStore.Add(createService("svc2", "fd00:10:96::1", 80))

	r := &Repair{
		interval:      0,
		serviceLister: serviceInformer.Lister(),
	}
	// Expected OVN commands
	fexec := ovntest.NewLooseCompareFakeExec()
	initializeClusterIPLBs(fexec)

	// OVN database is in Sync no operation expected
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + sctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grSctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerSCTPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingSCTPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + tcpLBUUID + " vips",
		Output: `{"10.96.0.10:80"="10.0.0.2:3456,10.0.0.3:3456", "[fd00:10:96::1]:80"="[2001:db8::1]:3456,[2001:db8::2]:3456"}`,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grTcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerTCPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingTCPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + udpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grUdpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerUDPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingUDPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --columns=_uuid --format=csv --data=bare --no-headings find acl action=reject",
		Output: "",
	})

	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	if err := r.runOnce(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestRepair_OVNMissingService(t *testing.T) {
	// Initialize informer cache
	serviceInformer := newServiceInformer()
	serviceStore := serviceInformer.Informer().GetStore()
	serviceStore.Add(createService("svc1", "10.96.0.10", 80))
	serviceStore.Add(createService("svc2", "fd00:10:96::1", 80))

	r := &Repair{
		interval:      0,
		serviceLister: serviceInformer.Lister(),
	}
	fexec := ovntest.NewFakeExec()
	initializeClusterIPLBs(fexec)

	// OVN database is in Sync no operation expected
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + sctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grSctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerSCTPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingSCTPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + tcpLBUUID + " vips",
		Output: `{"10.96.0.10:80"="10.0.0.2:3456,10.0.0.3:3456"}`,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grTcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerTCPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingTCPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + udpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grUdpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + workerUDPLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + idlingUDPLB + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --columns=_uuid --format=csv --data=bare --no-headings find acl action=reject",
		Output: "",
	})

	// The repair loop must do nothing, the controller will add the new service
	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	if err := r.runOnce(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func initializeClusterIPLBs(fexec *ovntest.FakeExec) {
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-sctp=yes",
		Output: sctpLBUUID,
	})

	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: tcpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-udp=yes",
		Output: udpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
		Output: "gateway1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=gateway1",
		Output: grSctpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-sctp=gateway1",
		Output: workerSCTPLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=gateway1",
		Output: grTcpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-tcp=gateway1",
		Output: workerTCPLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=gateway1",
		Output: grUdpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-udp=gateway1",
		Output: workerUDPLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-sctp=yes",
		Output: idlingSCTPLB,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
		Output: idlingTCPLB,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-udp=yes",
		Output: idlingUDPLB,
	})
}

func createService(name, ip string, port int) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "nsname"},
		Spec: v1.ServiceSpec{
			Type:       v1.ServiceTypeClusterIP,
			ClusterIP:  ip,
			ClusterIPs: []string{ip},
			Selector:   map[string]string{"foo": "bar"},
			Ports: []v1.ServicePort{{
				Port:       int32(port),
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt(3456),
			}},
		},
	}
}
