#!/bin/bash

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set -o xtrace

# ARGS:
# $1: IP of second interface of master
# $2: IP of second interface of minion
# $3: IP of third interface of master
# $4: Hostname of specific minion
# $5: Subnet to use

MASTER_OVERLAY_IP=$1
MINION_OVERLAY_IP=$2
PUBLIC_IP=$3
PUBLIC_SUBNET_MASK=$4
MINION_NAME=$5
MINION_SUBNET=$6
GW_IP=$7
OVN_EXTERNAL=$8

if [ -n "$OVN_EXTERNAL" ]; then
    PUBLIC_IP=`ifconfig enp0s9 | grep 'inet addr' | cut -d: -f2 | awk '{print $1}'`
    PUBLIC_SUBNET_MASK=`ifconfig enp0s9 | grep 'inet addr' | cut -d: -f4`
    GW_IP=`grep 'option routers' /var/lib/dhcp/dhclient.enp0s9.leases | head -1 | sed -e 's/;//' | awk '{print $3}'`
fi

cat > setup_minion_args.sh <<EOL
MASTER_OVERLAY_IP=$1
MINION_OVERLAY_IP=$2
PUBLIC_IP=$3
PUBLIC_SUBNET_MASK=$4
MINION_NAME=$5
MINION_SUBNET=$6
GW_IP=$7
OVN_EXTERNAL=$8
EOL

# Comment out the next line if you prefer TCP instead of SSL.
SSL="true"

# FIXME(mestery): Remove once Vagrant boxes allow apt-get to work again
sudo rm -rf /var/lib/apt/lists/*

# Add external repos to install docker and OVS from packages.
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates
echo "deb https://packages.wand.net.nz $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/wand.list
sudo curl https://packages.wand.net.nz/keyring.gpg -o /etc/apt/trusted.gpg.d/wand.gpg
sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
sudo su -c "echo \"deb https://apt.dockerproject.org/repo ubuntu-xenial main\" >> /etc/apt/sources.list.d/docker.list"
sudo apt-get update

# First, install docker
sudo apt-get purge lxc-docker
sudo apt-get install -y linux-image-extra-$(uname -r) linux-image-extra-virtual
sudo apt-get install -y docker-engine
sudo service docker start

# Install OVS and dependencies
sudo apt-get build-dep dkms
sudo apt-get install python-six openssl python-pip -y
sudo -H pip install --upgrade pip

sudo apt-get install openvswitch-datapath-dkms=2.8.1-1 -y
sudo apt-get install openvswitch-switch=2.8.1-1 openvswitch-common=2.8.1-1 libopenvswitch=2.8.1-1 -y
sudo -H pip install ovs

sudo apt-get install ovn-central=2.8.1-1 ovn-common=2.8.1-1 ovn-host=2.8.1-1 -y

if [ -n "$SSL" ]; then
    echo "PROTOCOL=ssl" >> setup_minion_args.sh
    # Install certificates
    pushd /etc/openvswitch
    sudo ovs-pki req ovncontroller
    sudo ovs-pki -b -d /vagrant/pki sign ovncontroller switch
    popd

    # Set ovn-controller SSL options in /etc/default/ovn-host
    sudo bash -c 'cat >> /etc/default/ovn-host <<EOF
OVN_CTL_OPTS="--ovn-controller-ssl-key=/etc/openvswitch/ovncontroller-privkey.pem  --ovn-controller-ssl-cert=/etc/openvswitch/ovncontroller-cert.pem --ovn-controller-ssl-bootstrap-ca-cert=/etc/openvswitch/ovnsb-ca.cert"
EOF'
else
  echo "PROTOCOL=tcp" >> setup_minion_args.sh
fi

# XXX: We only need this for ovn-k8s-gateway-helper
git clone https://github.com/openvswitch/ovn-kubernetes
pushd ovn-kubernetes
sudo -H pip install .
popd
sudo rm `which ovn-k8s-cni-overlay`
sudo rm `which ovn-k8s-overlay`

# Install golang
wget -nv https://dl.google.com/go/go1.9.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.9.2.linux-amd64.tar.gz
export PATH="/usr/local/go/bin:echo $PATH"
export GOPATH=$HOME/work

# Setup CNI directory
sudo mkdir -p /opt/cni/bin/

# Install OVN+K8S Integration
mkdir -p $HOME/work/src/github.com/openvswitch
pushd $HOME/work/src/github.com/openvswitch
git clone https://github.com/openvswitch/ovn-kubernetes
popd
pushd $HOME/work/src/github.com/openvswitch/ovn-kubernetes/go-controller
make 1>&2 2>/dev/null
sudo make install
popd

# Restore xtrace
$XTRACE
