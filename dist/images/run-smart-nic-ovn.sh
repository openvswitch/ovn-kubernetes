docker run --pid host --network host --user=0 --name ovn -dit --cap-add=SYS_NICE -v /var/run/dbus:/var/run/dbus:ro -v \
 /var/log/openvswitch:/var/log/openvswitch -v /var/log/openvswitch:/var/log/ovn -v  \
 /var/run/openvswitch:/var/run/openvswitch -v /var/run/openvswitch:/var/run/ovn -v $K8S_CACERT:$K8S_CACERT -v \
 /etc/ovn:/ovn-cert:ro -e OVN_DAEMONSET_VERSION=3 -e OVN_LOG_CONTROLLER="-vconsole:info" \
 -e K8S_APISERVER=$K8S_APISERVER -e OVN_KUBERNETES_NAMESPACE=ovn-kubernetes -e OVN_SSL_ENABLE=no \
 -e K8S_NODE=$K8S_NODE -e K8S_TOKEN=$K8S_TOKEN -e K8S_CACERT=$K8S_CACERT -e OVS_RUNDIR=/var/run/openvswitch \
 -e OVS_LOGDIR=/var/log/openvswitch --entrypoint=/root/ovnkube.sh  ovn-daemonset:aarch "ovn-controller"
