package services

import (
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
)

func Test_deleteVIPsFromOVN(t *testing.T) {
	config.Kubernetes.OVNEmptyLbEvents = true
	defer func() {
		config.Kubernetes.OVNEmptyLbEvents = false
	}()

	type args struct {
		vips   sets.String
		svc    *v1.Service
		ovnCmd []ovntest.ExpectedCmd
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty",
			args: args{
				vips: sets.NewString(),
				svc:  &v1.Service{},
				ovnCmd: []ovntest.ExpectedCmd{
					{
						Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
						Output: gatewayRouter1,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "delete existing vip",
			args: args{
				vips: sets.NewString("10.0.0.1:80/TCP"),
				svc: &v1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "ns"},
					Spec: v1.ServiceSpec{
						Type:       v1.ServiceTypeClusterIP,
						ClusterIP:  "10.0.0.1",
						ClusterIPs: []string{"10.0.0.1"},
						Selector:   map[string]string{"foo": "bar"},
						Ports: []v1.ServicePort{{
							Port:       80,
							Protocol:   v1.ProtocolTCP,
							TargetPort: intstr.FromInt(3456),
						}},
					},
				},
				ovnCmd: []ovntest.ExpectedCmd{
					{
						Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
						Output: gatewayRouter1,
					},
					{
						Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
						Output: loadbalancerTCP,
					},
					{
						Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips "10.0.0.1:80"`,
						Output: "",
					},
					{
						Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=2e290f10-3652-11eb-839b-a8a1590cda29",
						Output: "loadbalancer1",
					},
					{
						Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=2e290f10-3652-11eb-839b-a8a1590cda29_local",
						Output: "localloadbalancer1",
					},
					{
						Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-worker-lb-tcp=2e290f10-3652-11eb-839b-a8a1590cda29",
						Output: "workerlb",
					},
					{
						Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer loadbalancer1 vips "10.0.0.1:80"`,
						Output: "",
					},
					{
						Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer localloadbalancer1 vips "10.0.0.1:80"`,
						Output: "",
					},
					{
						Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer workerlb vips "10.0.0.1:80"`,
						Output: "",
					},
					{
						Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-idling-lb-tcp=yes",
						Output: idlingloadbalancerTCP,
					},
					{
						Cmd:    `ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda30 vips "10.0.0.1:80"`,
						Output: "",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := newServiceTracker()
			if len(tt.args.svc.Spec.ClusterIP) > 0 {
				st.updateKubernetesService(tt.args.svc)
			}
			// Expected OVN commands
			fexec := ovntest.NewFakeExec()
			for _, cmd := range tt.args.ovnCmd {
				cmd := cmd
				fexec.AddFakeCmd(&cmd)
			}
			err := util.SetExec(fexec)
			if err != nil {
				t.Errorf("fexec error: %v", err)
			}
			if err := deleteVIPsFromAllOVNBalancers(tt.args.vips, tt.args.svc.Name, tt.args.svc.Namespace); (err != nil) != tt.wantErr {
				t.Errorf("deleteVIPsFromOVN() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !fexec.CalledMatchesExpected() {
				t.Error(fexec.ErrorDesc())
			}
		})
	}
}

func TestServiceNeedsIdling(t *testing.T) {
	config.Kubernetes.OVNEmptyLbEvents = true
	defer func() {
		config.Kubernetes.OVNEmptyLbEvents = false
	}()

	tests := []struct {
		name        string
		annotations map[string]string
		needsIdling bool
	}{
		{
			name: "delete endpoint slice with no service",
			annotations: map[string]string{
				"foo": "bar",
			},
			needsIdling: false,
		},
		{
			name: "delete endpoint slice with no service",
			annotations: map[string]string{
				"idling.alpha.openshift.io/idled-at": "2021-03-25T21:58:54Z",
			},
			needsIdling: true,
		},

		{
			name: "delete endpoint slice with no service",
			annotations: map[string]string{
				"k8s.ovn.org/idled-at": "2021-03-25T21:58:54Z",
			},
			needsIdling: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if svcNeedsIdling(tt.annotations) != tt.needsIdling {
				t.Errorf("needs Idling does not match")
			}
		})
	}

}
