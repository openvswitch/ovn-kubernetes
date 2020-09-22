#
# This is the OpenShift ovn overlay network image.
# it provides an overlay network using ovs/ovn/ovn-kube
#
# The standard name for this image is ovn-kube

# Notes:
# This is for a development build where the ovn-kubernetes utilities
# are built in this Dockerfile and included in the image (instead of the rpm)
#
# This is based on centos:7
# openvswitch rpms are from
# http://cbs.centos.org/kojifiles/packages/openvswitch/2.9.0/4.el7/x86_64/
#
# So this file will change over time.

FROM centos:7

USER root

ENV PYTHONDONTWRITEBYTECODE yes

COPY kubernetes.repo /etc/yum.repos.d/kubernetes.repo
RUN INSTALL_PKGS=" \
	PyYAML bind-utils procps-ng openssl numactl-libs firewalld-filesystem \
	libpcap kubectl \
	iproute iputils strace socat \
	unbound-libs \
        " && \
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False $INSTALL_PKGS

RUN yum -y update && yum clean all && rm -rf /var/cache/yum/*

# Get a reasonable version of openvswitch (2.9.2 or higher)
# docker build --build-arg rpmArch=ARCH -f Dockerfile.centos -t some_tag .
# where ARCH can be x86_64 (default), aarch64, or ppc64le
ARG rpmArch=x86_64
ARG ovsVer=2.11.0
ARG ovsSubVer=4.el7
ARG dpdkVer=18.11.2
ARG dpdkSubVer=1.el7
ARG dpdkRpmUrl=http://mirror.centos.org/centos/7/extras/${rpmArch}/Packages/dpdk-${dpdkVer}-${dpdkSubVer}.${rpmArch}.rpm

RUN if [ "$(uname -m)" = "aarch64" ]; then dpdkRpmUrl=http://psw32.psw.net/altarch/7/extras/aarch64/Packages/dpdk-18.11-4.el7_6.aarch64.rpm; fi && rpm -i ${dpdkRpmUrl}
RUN rpm -i http://cbs.centos.org/kojifiles/packages/openvswitch/${ovsVer}/${ovsSubVer}/${rpmArch}/openvswitch-${ovsVer}-${ovsSubVer}.${rpmArch}.rpm
RUN rpm -i http://cbs.centos.org/kojifiles/packages/openvswitch/${ovsVer}/${ovsSubVer}/${rpmArch}/openvswitch-ovn-common-${ovsVer}-${ovsSubVer}.${rpmArch}.rpm
RUN rpm -i http://cbs.centos.org/kojifiles/packages/openvswitch/${ovsVer}/${ovsSubVer}/${rpmArch}/openvswitch-ovn-central-${ovsVer}-${ovsSubVer}.${rpmArch}.rpm
RUN rpm -i http://cbs.centos.org/kojifiles/packages/openvswitch/${ovsVer}/${ovsSubVer}/${rpmArch}/openvswitch-ovn-host-${ovsVer}-${ovsSubVer}.${rpmArch}.rpm
RUN rpm -i http://cbs.centos.org/kojifiles/packages/openvswitch/${ovsVer}/${ovsSubVer}/${rpmArch}/openvswitch-ovn-vtep-${ovsVer}-${ovsSubVer}.${rpmArch}.rpm
RUN rpm -i http://cbs.centos.org/kojifiles/packages/openvswitch/${ovsVer}/${ovsSubVer}/${rpmArch}/openvswitch-devel-${ovsVer}-${ovsSubVer}.${rpmArch}.rpm
RUN rm -rf /var/cache/yum

RUN mkdir -p /var/run/openvswitch

# Built in ../../go_controller, then the binaries are copied here.
# put things where they are in the rpm
RUN mkdir -p /usr/libexec/cni/
COPY ovnkube ovn-kube-util /usr/bin/
COPY ovn-k8s-cni-overlay /usr/libexec/cni/ovn-k8s-cni-overlay
COPY ovn-k8s-cni-smart-nic /usr/libexec/cni/ovn-k8s-cni-smart-nic

# ovnkube.sh is the entry point. This script examines environment
# variables to direct operation and configure ovn
COPY ovnkube.sh /root/
COPY ovndb-raft-functions.sh /root/
# override the rpm's ovn_k8s.conf with this local copy
COPY ovn_k8s.conf /etc/openvswitch/ovn_k8s.conf

# copy git commit number into image
COPY git_info /root

# iptables wrappers
COPY ./iptables-scripts/iptables /usr/sbin/
COPY ./iptables-scripts/iptables-save /usr/sbin/
COPY ./iptables-scripts/iptables-restore /usr/sbin/
COPY ./iptables-scripts/ip6tables /usr/sbin/
COPY ./iptables-scripts/ip6tables-save /usr/sbin/
COPY ./iptables-scripts/ip6tables-restore /usr/sbin/

LABEL io.k8s.display-name="ovn kubernetes" \
      io.k8s.description="This is a component of OpenShift Container Platform that provides an overlay network using ovn." \
      io.openshift.tags="openshift" \
      maintainer="Phil Cameron <pcameron@redhat.com>"

WORKDIR /root
ENTRYPOINT /root/ovnkube.sh
