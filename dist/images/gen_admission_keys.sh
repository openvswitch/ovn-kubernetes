#!/bin/bash

# Generate the CA cert and private key
openssl req -nodes -new -x509 -keyout ca.key -out ca.crt -subj "/CN=OVN-Kubernetes Admission Controller Webhook CA"
# Generate the private key for the admission server
openssl genrsa -out admission-server-tls.key 2048
# Generate a Certificate Signing Request (CSR) for the private key, and sign it with the private key of the CA.
openssl req -new -key admission-server-tls.key -subj "/CN=ovnkube-admission-controller.ovn-kubernetes.svc" \
    | openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -out admission-server-tls.crt
