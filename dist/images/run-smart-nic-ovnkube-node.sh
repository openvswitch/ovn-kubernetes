docker run --pid host --network host --user=0 --name ovn-node -dit --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
  --cap-add=SYS_PTRACE -v /:/host:ro  -v /var/run/dbus:/var/run/dbus:ro -v $K8S_CACERT:$K8S_CACERT \
  -v /var/log/ovn-kubernetes:/var/log/ovn-kubernetes  -v /var/run/openvswitch:/var/run/openvswitch/ -v \
  /var/run/penvswitch:/var/run/ovn/ -v /var/run/ovn-kubernetes:/var/run/ovn-kubernetes \
  -v /etc/cni/net.d -v /etc/ovn:/ovn-cert:ro -e OVN_DAEMONSET_VERSION=3 -e OVN_LOG_CONTROLLER="-vconsole:info" \
  -e OVN_NET_CIDR=$OVN_NET_CIDR -e OVN_SVC_CIDR=$OVN_SVC_CIDR -e K8S_NODE=$K8S_NODE  \
  -e OVN_GATEWAY_MODE=local -e  OVN_REMOTE_PROBE_INTERVAL=100000 -e K8S_APISERVER=$K8S_APISERVER \
  -e OVN_KUBERNETES_NAMESPACE=ovn-kubernetes -e OVN_SSL_ENABLE=no -e SMART_NIC="true" -e SMART_NIC_IP=$SMART_NIC_IP \
  -e K8S_TOKEN=$K8S_TOKEN -e K8S_CACERT=$K8S_CACERT --entrypoint=/root/ovnkube.sh  ovn-daemonset:aarch  "ovn-node"
