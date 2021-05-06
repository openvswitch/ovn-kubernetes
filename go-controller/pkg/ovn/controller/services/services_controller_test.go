package services

import (
	"fmt"
	"net"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	utilpointer "k8s.io/utils/pointer"
)

const (
	loadbalancerTCP       = "a08ea426-2288-11eb-a30b-a8a1590cda29"
	portGroupUUID         = "58a1ef18-3649-11eb-bd94-a8a1590cda29"
	gatewayRouter1        = "2e290f10-3652-11eb-839b-a8a1590cda29"
	logicalSwitch1        = "17bde5e8-3652-11eb-b53b-a8a1590cda29"
	idlingloadbalancerTCP = "a08ea426-2288-11eb-a30b-a8a1590cda30"
	clusterPortGroupUUID  = "a08ea426-2288-11eb-a30b-a8a1590cda31"
)

var alwaysReady = func() bool { return true }
var FakeGRs = "GR_1 GR_2"

type serviceController struct {
	*Controller
	serviceStore       cache.Store
	endpointSliceStore cache.Store
}

func newController() *serviceController {
	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	controller := NewController(client,
		informerFactory.Core().V1().Services(),
		informerFactory.Discovery().V1beta1().EndpointSlices(),
		clusterPortGroupUUID,
	)
	controller.servicesSynced = alwaysReady
	controller.endpointSlicesSynced = alwaysReady
	return &serviceController{
		controller,
		informerFactory.Core().V1().Services().Informer().GetStore(),
		informerFactory.Discovery().V1beta1().EndpointSlices().Informer().GetStore(),
	}
}

func TestSyncServices(t *testing.T) {
	ns := "testns"
	serviceName := "foo"
	config.Kubernetes.OVNEmptyLbEvents = true
	defer func() {
		config.Kubernetes.OVNEmptyLbEvents = false
	}()

	tests := []struct {
		name          string
		slice         *discovery.EndpointSlice
		service       *v1.Service
		updateTracker bool
		ovnCmd        []ovntest.ExpectedCmd
	}{

		{
			name: "create service from Single Stack Service without endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports:       []discovery.EndpointPort{},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints:   []discovery.Endpoint{},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       80,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt(3456),
					}},
				},
			},
			updateTracker: true,
			ovnCmd: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
					Output: idlingloadbalancerTCP,
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips \"192.168.1.1:80\"",
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
					Output: loadbalancerTCP,
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:\"192.168.1.1:80\"=\"\"",
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
					Output: gatewayRouter1,
				},
				{
					Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=%s", gatewayRouter1),
					Output: "load_balancer_1",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer load_balancer_1 vips \"192.168.1.1:80\"",
					Output: "",
				},
			},
		},
		{
			name: "create OVN LoadBalancer from Single Stack NodePort Service without endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports:       []discovery.EndpointPort{},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints:   []discovery.Endpoint{},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       80,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt(3456),
						NodePort:   32766,
					}},
				},
			},
			updateTracker: true,
			ovnCmd: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
					Output: gatewayRouter1,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 get logical_router 2e290f10-3652-11eb-839b-a8a1590cda29 external_ids:physical_ips`,
					Output: "5.5.5.5",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
					Output: gatewayRouter1,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 get logical_router 2e290f10-3652-11eb-839b-a8a1590cda29 external_ids:physical_ips`,
					Output: "5.5.5.5",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
					Output: idlingloadbalancerTCP,
				},
				{
					Cmd: `ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips "192.168.1.1:80"` +
						` -- --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips "5.5.5.5:32766"`,
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
					Output: loadbalancerTCP,
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:\"192.168.1.1:80\"=\"\"",
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
					Output: gatewayRouter1,
				},
				{
					Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=%s", gatewayRouter1),
					Output: "load_balancer_1",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer load_balancer_1 vips \"192.168.1.1:80\"",
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
					Output: gatewayRouter1,
				},
				{
					Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=%s", gatewayRouter1),
					Output: "load_balancer_1",
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 get logical_router 2e290f10-3652-11eb-839b-a8a1590cda29 external_ids:physical_ips`,
					Output: "5.5.5.5",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 set load_balancer load_balancer_1 vips:\"5.5.5.5:32766\"=\"\"",
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
					Output: gatewayRouter1,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 get logical_router 2e290f10-3652-11eb-839b-a8a1590cda29 external_ids:physical_ips`,
					Output: "5.5.5.5",
				},
			},
		},
		{
			name: "create OVN LoadBalancer from Single Stack Service with endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports: []discovery.EndpointPort{
					{
						Name:     utilpointer.StringPtr("tcp-example"),
						Protocol: protoPtr(v1.ProtocolTCP),
						Port:     utilpointer.Int32Ptr(int32(3456)),
					},
				},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Conditions: discovery.EndpointConditions{
							Ready: utilpointer.BoolPtr(true),
						},
						Addresses: []string{"10.0.0.2"},
						Topology:  map[string]string{"kubernetes.io/hostname": "node-1"},
					},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       80,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt(3456),
					}},
				},
			},
			updateTracker: false,
			ovnCmd: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
					Output: idlingloadbalancerTCP,
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips \"192.168.1.1:80\"",
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
					Output: loadbalancerTCP,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 set load_balancer ` + loadbalancerTCP + ` vips:"192.168.1.1:80"="10.0.0.2:3456"`,
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
					Output: FakeGRs,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_1`,
					Output: "load_balancer_1",
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer load_balancer_1 vips "192.168.1.1:80"`,
					Output: "",
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_2`,
					Output: "",
				},
			},
		},
		{
			name: "create OVN LoadBalancer from Dual Stack Service with dual stack endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports: []discovery.EndpointPort{
					{
						Name:     utilpointer.StringPtr("tcp-example"),
						Protocol: protoPtr(v1.ProtocolTCP),
						Port:     utilpointer.Int32Ptr(int32(3456)),
					},
				},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Conditions: discovery.EndpointConditions{
							Ready: utilpointer.BoolPtr(true),
						},
						Addresses: []string{"10.0.0.2"},
						Topology:  map[string]string{"kubernetes.io/hostname": "node-1"},
					},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       80,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt(3456),
					}},
				},
			},
			updateTracker: false,
			ovnCmd: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
					Output: idlingloadbalancerTCP,
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips \"192.168.1.1:80\"",
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
					Output: loadbalancerTCP,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:"192.168.1.1:80"="10.0.0.2:3456"`,
					Output: "",
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
					Output: FakeGRs,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_1`,
					Output: "load_balancer_1",
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer load_balancer_1 vips "192.168.1.1:80"`,
					Output: "",
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_2`,
					Output: "",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := newController()
			// Add objects to the Store
			controller.endpointSliceStore.Add(tt.slice)
			controller.serviceStore.Add(tt.service)
			if tt.updateTracker {
				controller.serviceTracker.updateKubernetesService(tt.service, "")
			}

			// Expected OVN commands
			fexec := ovntest.NewLooseCompareFakeExec()
			for _, cmd := range tt.ovnCmd {
				cmd := cmd
				fexec.AddFakeCmd(&cmd)
			}
			err := util.SetExec(fexec)
			if err != nil {
				t.Errorf("fexec error: %v", err)
			}
			err = controller.syncServices(ns + "/" + serviceName)
			if err != nil {
				t.Errorf("syncServices error: %v", err)
			}

			if !fexec.CalledMatchesExpected() {
				t.Error(fexec.ErrorDesc())
			}
		})
	}
}

// A service can mutate its ports, we need to be sure we don´t left dangling ports
func TestUpdateServicePorts(t *testing.T) {
	config.Kubernetes.OVNEmptyLbEvents = true
	defer func() {
		config.Kubernetes.OVNEmptyLbEvents = false
	}()

	// Expected OVN commands
	fexec := ovntest.NewFakeExec()
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
		Output: idlingloadbalancerTCP,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips \"192.168.1.1:80\"",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: loadbalancerTCP,
	})
	// Add a new loadbalancer with the Service Port 80
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:"192.168.1.1:80"="10.0.0.2:3456"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
		Output: FakeGRs,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_1`,
		Output: "load_balancer_1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_2`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer load_balancer_1 vips "192.168.1.1:80"`,
		Output: "",
	})
	// update service starts here
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
		Output: idlingloadbalancerTCP,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips \"192.168.1.1:8888\"",
		Output: idlingloadbalancerTCP,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: loadbalancerTCP,
	})
	// Add a new loadbalancer with the new Service Port 8888
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:"192.168.1.1:8888"="10.0.0.2:3456"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
		Output: FakeGRs,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_1`,
		Output: "load_balancer_1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_2`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer load_balancer_1 vips "192.168.1.1:8888"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
		Output: gatewayRouter1,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: loadbalancerTCP,
	})
	// Remove the old ServicePort
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=%s", gatewayRouter1),
		Output: "load_balancer_1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-tcp=2e290f10-3652-11eb-839b-a8a1590cda29"),
		Output: "node_load_balancer_1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd: `ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips "192.168.1.1:80"` +
			` -- --if-exists remove load_balancer load_balancer_1 vips "192.168.1.1:80"` +
			` -- --if-exists remove load_balancer node_load_balancer_1 vips "192.168.1.1:80"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
		Output: idlingloadbalancerTCP,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips \"192.168.1.1:80\"",
		Output: "",
	})

	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	ns := "testns"
	serviceName := "foo"
	slice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName + "ab23",
			Namespace: ns,
			Labels:    map[string]string{discovery.LabelServiceName: serviceName},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     utilpointer.StringPtr("tcp-example"),
				Protocol: protoPtr(v1.ProtocolTCP),
				Port:     utilpointer.Int32Ptr(int32(3456)),
			},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Conditions: discovery.EndpointConditions{
					Ready: utilpointer.BoolPtr(true),
				},
				Addresses: []string{"10.0.0.2"},
				Topology:  map[string]string{"kubernetes.io/hostname": "node-1"},
			},
		},
	}
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
		Spec: v1.ServiceSpec{
			Type:       v1.ServiceTypeClusterIP,
			ClusterIP:  "192.168.1.1",
			ClusterIPs: []string{"192.168.1.1"},
			Selector:   map[string]string{"foo": "bar"},
			Ports: []v1.ServicePort{{
				Port:       80,
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt(3456),
			}},
		},
	}
	controller := newController()
	// Process the first service
	controller.endpointSliceStore.Add(slice)
	controller.serviceStore.Add(service)
	controller.syncServices(ns + "/" + serviceName)

	// Update the service with a different Port
	serviceNew := service.DeepCopy()
	serviceNew.Spec.Ports[0].Port = 8888
	controller.serviceStore.Delete(service)
	controller.serviceStore.Add(serviceNew)
	// sync service
	controller.syncServices(ns + "/" + serviceName)
	if controller.serviceTracker.hasServiceVIP(serviceName, ns, "192.168.1.1:80", v1.ProtocolTCP) {
		t.Fatalf("Service with port 80 should not exist")
	}
	if !controller.serviceTracker.hasServiceVIP(serviceName, ns, "192.168.1.1:8888", v1.ProtocolTCP) {
		t.Fatalf("Service with port 8888 should exist")
	}
	if !fexec.CalledMatchesExpected() {
		t.Error(fexec.ErrorDesc())
	}
}

// A service can mutate its ports, we need to be sure we don´t left dangling ports
func TestUpdateServiceEndpointsToHost(t *testing.T) {
	config.Kubernetes.OVNEmptyLbEvents = true
	defer func() {
		config.Kubernetes.OVNEmptyLbEvents = false
	}()

	// Expected OVN commands
	fexec := ovntest.NewFakeExec()
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
		Output: idlingloadbalancerTCP,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips \"192.168.1.1:80\"",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: loadbalancerTCP,
	})
	// Add a new loadbalancer with the Service Port 80
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:"192.168.1.1:80"="10.128.0.2:3456"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
		Output: FakeGRs,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_1`,
		Output: "load_balancer_1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-tcp=1`,
		Output: "load_balancer_worker_1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_2`,
		Output: "load_balancer_2",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-tcp=2`,
		Output: "load_balancer_worker_2",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd: `ovn-nbctl --timeout=15 --if-exists remove load_balancer load_balancer_1 vips "192.168.1.1:80"` +
			` -- --if-exists remove load_balancer load_balancer_worker_1 vips "192.168.1.1:80"` +
			` -- --if-exists remove load_balancer load_balancer_2 vips "192.168.1.1:80"` +
			` -- --if-exists remove load_balancer load_balancer_worker_2 vips "192.168.1.1:80"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: loadbalancerTCP,
	})
	// Update endpoints to have host endpoint in shared gw mode
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
		Output: FakeGRs,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_1`,
		Output: "load_balancer_1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 get logical_router GR_1 external_ids:physical_ips`,
		Output: "2.2.2.2",
	})
	// endpoint is self node IP, so need to use special masquerade endpoint
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 set load_balancer load_balancer_1 vips:"192.168.1.1:80"="169.254.169.2:3456"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-tcp=1`,
		Output: "load_balancer_worker_1",
	})
	// use regular backend on the worker switch LB
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 set load_balancer load_balancer_worker_1 vips:"192.168.1.1:80"="2.2.2.2:3456"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_2`,
		Output: "load_balancer_2",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 get logical_router GR_2 external_ids:physical_ips`,
		Output: "2.2.2.3",
	})
	// adding to second node will not use special masquerade
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 set load_balancer load_balancer_2 vips:"192.168.1.1:80"="2.2.2.2:3456"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-tcp=2`,
		Output: "load_balancer_worker_2",
	})
	// and regular endpoint IP on the 2nd worker switch
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 set load_balancer load_balancer_worker_2 vips:"192.168.1.1:80"="2.2.2.2:3456"`,
		Output: "",
	})
	// Ensure the VIP entry is removed on the cluster wide TCP load balancer
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips "192.168.1.1:80"`,
		Output: "",
	})

	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	ns := "testns"
	serviceName := "foo"
	slice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName + "ab23",
			Namespace: ns,
			Labels:    map[string]string{discovery.LabelServiceName: serviceName},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     utilpointer.StringPtr("tcp-example"),
				Protocol: protoPtr(v1.ProtocolTCP),
				Port:     utilpointer.Int32Ptr(int32(3456)),
			},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Conditions: discovery.EndpointConditions{
					Ready: utilpointer.BoolPtr(true),
				},
				Addresses: []string{"10.128.0.2"},
				Topology:  map[string]string{"kubernetes.io/hostname": "node-1"},
			},
		},
	}
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
		Spec: v1.ServiceSpec{
			Type:       v1.ServiceTypeClusterIP,
			ClusterIP:  "192.168.1.1",
			ClusterIPs: []string{"192.168.1.1"},
			Selector:   map[string]string{"foo": "bar"},
			Ports: []v1.ServicePort{{
				Port:       80,
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt(3456),
			}},
		},
	}
	oldClusterSubnet := config.Default.ClusterSubnets
	oldGwMode := config.Gateway.Mode
	defer func() {
		config.Gateway.Mode = oldGwMode
		config.Default.ClusterSubnets = oldClusterSubnet
	}()
	_, cidr, _ := net.ParseCIDR("10.128.0.0/24")
	config.Default.ClusterSubnets = []config.CIDRNetworkEntry{{cidr, 26}}
	config.Gateway.Mode = config.GatewayModeShared
	controller := newController()
	// Process the first service
	controller.endpointSliceStore.Add(slice)
	controller.serviceStore.Add(service)
	controller.syncServices(ns + "/" + serviceName)

	// Update endpoints with host network pod
	epsNew := slice.DeepCopy()
	epsNew.Endpoints = []discovery.Endpoint{
		{
			Conditions: discovery.EndpointConditions{
				Ready: utilpointer.BoolPtr(true),
			},
			Addresses: []string{"2.2.2.2"},
			Topology:  map[string]string{"kubernetes.io/hostname": "node-1"},
		}}
	controller.endpointSliceStore.Delete(slice)
	controller.endpointSliceStore.Add(epsNew)
	// sync service
	controller.syncServices(ns + "/" + serviceName)

	if !fexec.CalledMatchesExpected() {
		t.Error(fexec.ErrorDesc())
	}
}

// Update a service that was not idled, change endpoints that are both non host network and ensure that
// there are no unnecessary remove cmds
func TestUpdateServiceEndpointsLessRemoveOps(t *testing.T) {
	config.Kubernetes.OVNEmptyLbEvents = true
	defer func() {
		config.Kubernetes.OVNEmptyLbEvents = false
	}()
	// Expected OVN commands
	fexec := ovntest.NewFakeExec()
	// First sync we expect the redundant remove commands
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
		Output: idlingloadbalancerTCP,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips \"192.168.1.1:80\"",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: loadbalancerTCP,
	})
	// Add a new loadbalancer with the Service Port 80
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:"192.168.1.1:80"="10.128.0.2:3456"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
		Output: FakeGRs,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_1`,
		Output: "load_balancer_1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-tcp=1`,
		Output: "load_balancer_worker_1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_2`,
		Output: "load_balancer_2",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-tcp=2`,
		Output: "load_balancer_worker_2",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd: `ovn-nbctl --timeout=15 --if-exists remove load_balancer load_balancer_1 vips "192.168.1.1:80"` +
			` -- --if-exists remove load_balancer load_balancer_worker_1 vips "192.168.1.1:80"` +
			` -- --if-exists remove load_balancer load_balancer_2 vips "192.168.1.1:80"` +
			` -- --if-exists remove load_balancer load_balancer_worker_2 vips "192.168.1.1:80"`,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: loadbalancerTCP,
	})
	// Update endpoints to have new endpoint in shared gw mode, should not call redundant remove ops on idling, worker lbs
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    `ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:"192.168.1.1:80"="10.128.0.6:3456"`,
		Output: "",
	})

	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	ns := "testns"
	serviceName := "foo"
	slice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName + "ab23",
			Namespace: ns,
			Labels:    map[string]string{discovery.LabelServiceName: serviceName},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     utilpointer.StringPtr("tcp-example"),
				Protocol: protoPtr(v1.ProtocolTCP),
				Port:     utilpointer.Int32Ptr(int32(3456)),
			},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Conditions: discovery.EndpointConditions{
					Ready: utilpointer.BoolPtr(true),
				},
				Addresses: []string{"10.128.0.2"},
				Topology:  map[string]string{"kubernetes.io/hostname": "node-1"},
			},
		},
	}
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
		Spec: v1.ServiceSpec{
			Type:       v1.ServiceTypeClusterIP,
			ClusterIP:  "192.168.1.1",
			ClusterIPs: []string{"192.168.1.1"},
			Selector:   map[string]string{"foo": "bar"},
			Ports: []v1.ServicePort{{
				Port:       80,
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt(3456),
			}},
		},
	}
	oldClusterSubnet := config.Default.ClusterSubnets
	oldGwMode := config.Gateway.Mode
	defer func() {
		config.Gateway.Mode = oldGwMode
		config.Default.ClusterSubnets = oldClusterSubnet
	}()
	_, cidr, _ := net.ParseCIDR("10.128.0.0/24")
	config.Default.ClusterSubnets = []config.CIDRNetworkEntry{{cidr, 26}}
	config.Gateway.Mode = config.GatewayModeShared
	controller := newController()
	// Process the first service
	controller.endpointSliceStore.Add(slice)
	controller.serviceStore.Add(service)
	controller.syncServices(ns + "/" + serviceName)

	// Update endpoints with host network pod
	epsNew := slice.DeepCopy()
	epsNew.Endpoints = []discovery.Endpoint{
		{
			Conditions: discovery.EndpointConditions{
				Ready: utilpointer.BoolPtr(true),
			},
			Addresses: []string{"10.128.0.6"},
			Topology:  map[string]string{"kubernetes.io/hostname": "node-1"},
		}}
	controller.endpointSliceStore.Delete(slice)
	controller.endpointSliceStore.Add(epsNew)
	// sync service
	controller.syncServices(ns + "/" + serviceName)

	if !fexec.CalledMatchesExpected() {
		t.Error(fexec.ErrorDesc())
	}
}

// protoPtr takes a Protocol and returns a pointer to it.
func protoPtr(proto v1.Protocol) *v1.Protocol {
	return &proto
}
