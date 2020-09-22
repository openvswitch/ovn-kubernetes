#!/bin/bash
#set -x

#Always exit on errors
set -e

# The script renders j2 templates into yaml files in ../yaml/

# ensure j2 renderer installed
pip freeze | grep j2cli || pip install j2cli[yaml] --user
export PATH=~/.local/bin:$PATH

OVN_IMAGE=""
OVN_IMAGE_PULL_POLICY=""
OVN_NET_CIDR=""
OVN_SVC_DIDR=""
OVN_K8S_APISERVER=""
OVN_GATEWAY_MODE=""
OVN_GATEWAY_OPTS=""
OVN_DB_REPLICAS=""
OVN_MTU=""
OVN_SSL_ENABLE=""
KIND=""
OVN_UNPRIVILEGED_MODE=""
MASTER_LOGLEVEL=""
NODE_LOGLEVEL=""
OVN_LOGLEVEL_NORTHD=""
OVN_LOGLEVEL_NB=""
OVN_LOGLEVEL_SB=""
OVN_LOGLEVEL_CONTROLLER=""
OVN_LOGLEVEL_NBCTLD=""
OVNKUBE_LOGFILE_MAXSIZE=""
OVNKUBE_LOGFILE_MAXBACKUPS=""
OVNKUBE_LOGFILE_MAXAGE=""
OVN_MASTER_COUNT=""
OVN_REMOTE_PROBE_INTERVAL=""
OVN_HYBRID_OVERLAY_ENABLE=""
OVN_DISABLE_SNAT_MULTIPLE_GWS=""
OVN_MULTICAST_ENABLE=""
OVN_EGRESSIP_ENABLE=

# Parse parameters given as arguments to this script.
while [ "$1" != "" ]; do
  PARAM=$(echo $1 | awk -F= '{print $1}')
  VALUE=$(echo $1 | cut -d= -f2-)
  case $PARAM in
  --image)
    OVN_IMAGE=$VALUE
    ;;
  --image-pull-policy)
    OVN_IMAGE_PULL_POLICY=$VALUE
    ;;
  --gateway-mode)
    OVN_GATEWAY_MODE=$VALUE
    ;;
  --gateway-options)
    OVN_GATEWAY_OPTS=$VALUE
    ;;
  --net-cidr)
    OVN_NET_CIDR=$VALUE
    ;;
  --svc-cidr)
    OVN_SVC_CIDR=$VALUE
    ;;
  --k8s-apiserver)
    OVN_K8S_APISERVER=$VALUE
    ;;
  --db-replicas)
    OVN_DB_REPLICAS=$VALUE
    ;;
  --mtu)
    OVN_MTU=$VALUE
    ;;
  --kind)
    KIND=true
    ;;
  --ovn-unprivileged-mode)
    OVN_UNPRIVILEGED_MODE=$VALUE
    ;;
  --master-loglevel)
    MASTER_LOGLEVEL=$VALUE
    ;;
  --node-loglevel)
    NODE_LOGLEVEL=$VALUE
    ;;
  --ovn-loglevel-northd)
    OVN_LOGLEVEL_NORTHD=$VALUE
    ;;
  --ovn-loglevel-nb)
    OVN_LOGLEVEL_NB=$VALUE
    ;;
  --ovn-loglevel-sb)
    OVN_LOGLEVEL_SB=$VALUE
    ;;
  --ovn-loglevel-controller)
    OVN_LOGLEVEL_CONTROLLER=$VALUE
    ;;
  --ovn-loglevel-nbctld)
    OVN_LOGLEVEL_NBCTLD=$VALUE
    ;;
  --ovnkube-logfile-maxsize)
    OVNKUBE_LOGFILE_MAXSIZE=$VALUE
    ;;
  --ovnkube-logfile-maxbackups)
    OVNKUBE_LOGFILE_MAXBACKUPS=$VALUE
    ;;
  --ovnkube-logfile-maxage)
    OVNKUBE_LOGFILE_MAXAGE=$VALUE
    ;;
  --ssl)
    OVN_SSL_ENABLE="yes"
    ;;
  --ovn_nb_raft_election_timer)
    OVN_NB_RAFT_ELECTION_TIMER=$VALUE
    ;;
  --ovn_sb_raft_election_timer)
    OVN_SB_RAFT_ELECTION_TIMER=$VALUE
    ;;
  --ovn-master-count)
    OVN_MASTER_COUNT=$VALUE
    ;;
  --ovn-nb-port)
    OVN_NB_PORT=$VALUE
    ;;
  --ovn-sb-port)
    OVN_SB_PORT=$VALUE
    ;;
  --ovn-nb-raft-port)
    OVN_NB_RAFT_PORT=$VALUE
    ;;
  --ovn-sb-raft-port)
    OVN_SB_RAFT_PORT=$VALUE
    ;;
  --hybrid-enabled)
    OVN_HYBRID_OVERLAY_ENABLE=$VALUE
    ;;
  --disable-snat-multiple-gws)
    OVN_DISABLE_SNAT_MULTIPLE_GWS=$VALUE
    ;;
  --multicast-enabled)
    OVN_MULTICAST_ENABLE=$VALUE
    ;;
  --egress-ip-enable)
    OVN_EGRESSIP_ENABLE=$VALUE
    ;;
  *)
    echo "WARNING: unknown parameter \"$PARAM\""
    exit 1
    ;;
  esac
  shift
done

# Create the daemonsets with the desired image
# They are expanded into daemonsets in ../yaml

image=${OVN_IMAGE:-"docker.io/ovnkube/ovn-daemonset:latest"}
echo "image: ${image}"

image_pull_policy=${OVN_IMAGE_PULL_POLICY:-"IfNotPresent"}
echo "imagePullPolicy: ${image_pull_policy}"

ovn_gateway_mode=${OVN_GATEWAY_MODE}
echo "ovn_gateway_mode: ${ovn_gateway_mode}"

ovn_gateway_opts=${OVN_GATEWAY_OPTS}
echo "ovn_gateway_opts: ${ovn_gateway_opts}"

ovn_db_replicas=${OVN_DB_REPLICAS:-3}
echo "ovn_db_replicas: ${ovn_db_replicas}"
ovn_db_minAvailable=$(((${ovn_db_replicas} + 1) / 2))
echo "ovn_db_minAvailable: ${ovn_db_minAvailable}"
master_loglevel=${MASTER_LOGLEVEL:-"4"}
echo "master_loglevel: ${master_loglevel}"
node_loglevel=${NODE_LOGLEVEL:-"4"}
echo "node_loglevel: ${node_loglevel}"
ovn_loglevel_northd=${OVN_LOGLEVEL_NORTHD:-"-vconsole:info -vfile:info"}
echo "ovn_loglevel_northd: ${ovn_loglevel_northd}"
ovn_loglevel_nb=${OVN_LOGLEVEL_NB:-"-vconsole:info -vfile:info"}
echo "ovn_loglevel_nb: ${ovn_loglevel_nb}"
ovn_loglevel_sb=${OVN_LOGLEVEL_SB:-"-vconsole:info -vfile:info"}
echo "ovn_loglevel_sb: ${ovn_loglevel_sb}"
ovn_loglevel_controller=${OVN_LOGLEVEL_CONTROLLER:-"-vconsole:info"}
echo "ovn_loglevel_controller: ${ovn_loglevel_controller}"
ovn_loglevel_nbctld=${OVN_LOGLEVEL_NBCTLD:-"-vconsole:info"}
echo "ovn_loglevel_nbctld: ${ovn_loglevel_nbctld}"
ovnkube_logfile_maxsize=${OVNKUBE_LOGFILE_MAXSIZE:-"100"}
echo "ovnkube_logfile_maxsize: ${ovnkube_logfile_maxsize}"
ovnkube_logfile_maxbackups=${OVNKUBE_LOGFILE_MAXBACKUPS:-"5"}
echo "ovnkube_logfile_maxbackups: ${ovnkube_logfile_maxbackups}"
ovnkube_logfile_maxage=${OVNKUBE_LOGFILE_MAXAGE:-"5"}
echo "ovnkube_logfile_maxage: ${ovnkube_logfile_maxage}"
ovn_hybrid_overlay_enable=${OVN_HYBRID_OVERLAY_ENABLE}
echo "ovn_hybrid_overlay_enable: ${ovn_hybrid_overlay_enable}"
ovn_egress_ip_enable=${OVN_EGRESSIP_ENABLE}
echo "ovn_egress_ip_enable: ${ovn_egress_ip_enable}"
ovn_hybrid_overlay_net_cidr=${OVN_HYBRID_OVERLAY_NET_CIDR}
echo "ovn_hybrid_overlay_net_cidr: ${ovn_hybrid_overlay_net_cidr}"
ovn_disable_snat_multiple_gws=${OVN_DISABLE_SNAT_MULTIPLE_GWS}
echo "ovn_disable_snat_multiple_gws: ${ovn_disable_snat_multiple_gws}"
ovn_ssl_en=${OVN_SSL_ENABLE:-"no"}
echo "ovn_ssl_enable: ${ovn_ssl_en}"
ovn_unprivileged_mode=${OVN_UNPRIVILEGED_MODE:-"no"}
echo "ovn_unprivileged_mode: ${ovn_unprivileged_mode}"
ovn_nb_raft_election_timer=${OVN_NB_RAFT_ELECTION_TIMER:-1000}
echo "ovn_nb_raft_election_timer: ${ovn_nb_raft_election_timer}"
ovn_sb_raft_election_timer=${OVN_SB_RAFT_ELECTION_TIMER:-1000}
echo "ovn_sb_raft_election_timer: ${ovn_sb_raft_election_timer}"
ovn_master_count=${OVN_MASTER_COUNT:-"1"}
echo "ovn_master_count: ${ovn_master_count}"
ovn_remote_probe_interval=${OVN_REMOTE_PROBE_INTERVAL:-"100000"}
echo "ovn_remote_probe_interval: ${ovn_remote_probe_interval}"
ovn_nb_port=${OVN_NB_PORT:-6641}
echo "ovn_nb_port: ${ovn_nb_port}"
ovn_sb_port=${OVN_SB_PORT:-6642}
echo "ovn_sb_port: ${ovn_sb_port}"
ovn_nb_raft_port=${OVN_NB_RAFT_PORT:-6643}
echo "ovn_nb_raft_port: ${ovn_nb_raft_port}"
ovn_sb_raft_port=${OVN_SB_RAFT_PORT:-6644}
echo "ovn_sb_raft_port: ${ovn_sb_raft_port}"
ovn_multicast_enable=${OVN_MULTICAST_ENABLE}
echo "ovn_multicast_enable: ${ovn_multicast_enable}"

ovn_image=${image} \
  ovn_image_pull_policy=${image_pull_policy} \
  kind=${KIND} \
  ovn_unprivileged_mode=${ovn_unprivileged_mode} \
  ovn_gateway_mode=${ovn_gateway_mode} \
  ovn_gateway_opts=${ovn_gateway_opts} \
  ovnkube_node_loglevel=${node_loglevel} \
  ovn_loglevel_controller=${ovn_loglevel_controller} \
  ovnkube_logfile_maxsize=${ovnkube_logfile_maxsize} \
  ovnkube_logfile_maxbackups=${ovnkube_logfile_maxbackups} \
  ovnkube_logfile_maxage=${ovnkube_logfile_maxage} \
  ovn_hybrid_overlay_net_cidr=${ovn_hybrid_overlay_net_cidr} \
  ovn_hybrid_overlay_enable=${ovn_hybrid_overlay_enable} \
  ovn_disable_snat_multiple_gws=${ovn_disable_snat_multiple_gws} \
  ovn_multicast_enable=${ovn_multicast_enable} \
  ovn_egress_ip_enable=${ovn_egress_ip_enable} \
  ovn_ssl_en=${ovn_ssl_en} \
  ovn_remote_probe_interval=${ovn_remote_probe_interval} \
  j2 ../templates/ovnkube-node.yaml.j2 -o ../yaml/ovnkube-node.yaml

ovn_image=${image} \
  ovn_image_pull_policy=${image_pull_policy} \
  ovnkube_master_loglevel=${master_loglevel} \
  ovn_loglevel_northd=${ovn_loglevel_northd} \
  ovn_loglevel_nbctld=${ovn_loglevel_nbctld} \
  ovnkube_logfile_maxsize=${ovnkube_logfile_maxsize} \
  ovnkube_logfile_maxbackups=${ovnkube_logfile_maxbackups} \
  ovnkube_logfile_maxage=${ovnkube_logfile_maxage} \
  ovn_hybrid_overlay_net_cidr=${ovn_hybrid_overlay_net_cidr} \
  ovn_hybrid_overlay_enable=${ovn_hybrid_overlay_enable} \
  ovn_disable_snat_multiple_gws=${ovn_disable_snat_multiple_gws} \
  ovn_multicast_enable=${ovn_multicast_enable} \
  ovn_egress_ip_enable=${ovn_egress_ip_enable} \
  ovn_ssl_en=${ovn_ssl_en} \
  ovn_master_count=${ovn_master_count} \
  ovn_gateway_mode=${ovn_gateway_mode} \
  j2 ../templates/ovnkube-master.yaml.j2 -o ../yaml/ovnkube-master.yaml

ovn_image=${image} \
  ovn_image_pull_policy=${image_pull_policy} \
  ovn_loglevel_nb=${ovn_loglevel_nb} \
  ovn_loglevel_sb=${ovn_loglevel_sb} \
  ovn_ssl_en=${ovn_ssl_en} \
  ovn_nb_port=${ovn_nb_port} \
  ovn_sb_port=${ovn_sb_port} \
  j2 ../templates/ovnkube-db.yaml.j2 -o ../yaml/ovnkube-db.yaml

ovn_image=${image} \
  ovn_image_pull_policy=${image_pull_policy} \
  ovn_db_replicas=${ovn_db_replicas} \
  ovn_db_minAvailable=${ovn_db_minAvailable} \
  ovn_loglevel_nb=${ovn_loglevel_nb} ovn_loglevel_sb=${ovn_loglevel_sb} \
  ovn_ssl_en=${ovn_ssl_en} \
  ovn_nb_raft_election_timer=${ovn_nb_raft_election_timer} \
  ovn_sb_raft_election_timer=${ovn_sb_raft_election_timer} \
  ovn_nb_port=${ovn_nb_port} \
  ovn_sb_port=${ovn_sb_port} \
  ovn_nb_raft_port=${ovn_nb_raft_port} \
  ovn_sb_raft_port=${ovn_sb_raft_port} \
  j2 ../templates/ovnkube-db-raft.yaml.j2 -o ../yaml/ovnkube-db-raft.yaml

ovn_image=${image} \
  ovn_image_pull_policy=${image_pull_policy} \
  ovn_unprivileged_mode=${ovn_unprivileged_mode} \
  j2 ../templates/ovs-node.yaml.j2 -o ../yaml/ovs-node.yaml

# smart nic nic daemonset
ovn_image=${image} \
  ovn_image_pull_policy=${image_pull_policy} \
  j2 ../templates/ovnkube-smart-nic-cni.yaml.j2 -o ../yaml/ovnkube-smart-nic-cni.yaml

# ovn-setup.yaml
net_cidr=${OVN_NET_CIDR:-"10.128.0.0/14/23"}
svc_cidr=${OVN_SVC_CIDR:-"172.30.0.0/16"}
k8s_apiserver=${OVN_K8S_APISERVER:-"10.0.2.16:6443"}
mtu=${OVN_MTU:-1400}

echo "net_cidr: ${net_cidr}"
echo "svc_cidr: ${svc_cidr}"
echo "k8s_apiserver: ${k8s_apiserver}"
echo "mtu: ${mtu}"

net_cidr=${net_cidr} svc_cidr=${svc_cidr} \
  mtu_value=${mtu} k8s_apiserver=${k8s_apiserver} \
  j2 ../templates/ovn-setup.yaml.j2 -o ../yaml/ovn-setup.yaml

cp ../templates/ovnkube-monitor.yaml.j2 ../yaml/ovnkube-monitor.yaml
cp ../templates/k8s.ovn.org_egressfirewalls.yaml.j2 ../yaml/k8s.ovn.org_egressfirewalls.yaml
cp ../templates/k8s.ovn.org_egressips.yaml.j2 ../yaml/k8s.ovn.org_egressips.yaml

exit 0
