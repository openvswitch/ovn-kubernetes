#!/bin/bash

cmd=${1:-""}

bracketify() { case "$1" in *:*) echo "[$1]" ;; *) echo "$1" ;; esac; }

run-northd() {
    set -xe
    if [[ -f "/env/_master" ]]; then
        set -o allexport
        source "/env/_master"
        set +o allexport
    fi

    echo "$(date -Iseconds) - starting ovn-northd"
    exec ovn-northd \
        --no-chdir "-vconsole:${OVN_LOG_LEVEL}" -vfile:off \
        --ovnnb-db "${OVN_NB_DB_LIST}" \
        --ovnsb-db "${OVN_SB_DB_LIST}" \
        --pidfile /var/run/ovn/ovn-northd.pid \
        -p /ovn-cert/tls.key \
        -c /ovn-cert/tls.crt \
        -C /ovn-ca/ca-bundle.crt
}

run-nbdb() {
    set -xe
    if [[ -f "/env/_master" ]]; then
        set -o allexport
        source "/env/_master"
        set +o allexport
    fi
    

    # initialize variables
    ovn_kubernetes_namespace=openshift-ovn-kubernetes
    ovndb_ctl_ssl_opts="-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt"
    transport="ssl"
    ovn_raft_conn_ip_url_suffix=""
    if [[ "${K8S_NODE_IP}" == *":"* ]]; then
        ovn_raft_conn_ip_url_suffix=":[::]"
    fi
    db="nb"
    db_port="${OVN_NB_PORT}"
    ovn_db_file="/etc/ovn/ovn${db}_db.db"

    MASTER_IP="${OVN_MASTER_IP}"
    echo "$(date -Iseconds) - starting nbdb  MASTER_IP=${MASTER_IP}, K8S_NODE_IP=${K8S_NODE_IP}"
    initial_raft_create=true
    initialize="false"

    if [[ ! -e ${ovn_db_file} ]]; then
        initialize="true"
    fi

    if [[ "${initialize}" == "true" ]]; then
        # check to see if a cluster already exists. If it does, just join it.
        counter=0
        cluster_found=false
        while [ $counter -lt 5 ]; do
            if cluster_exists ${db} ${db_port}; then
                cluster_found=true
                break
            fi
            sleep 1
            counter=$((counter + 1))
        done

        if ${cluster_found}; then
            echo "Cluster already exists for DB: ${db}"
            initial_raft_create=false
            # join existing cluster
            exec /usr/share/ovn/scripts/ovn-ctl \
                --db-nb-cluster-local-port=${OVN_NB_RAFT_PORT} \
                --db-nb-cluster-remote-port=${OVN_NB_RAFT_PORT} \
                --db-nb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
                --db-nb-cluster-remote-addr=${init_ip} \
                --no-monitor \
                --db-nb-cluster-local-proto=ssl \
                --db-nb-cluster-remote-proto=ssl \
                --ovn-nb-db-ssl-key=/ovn-cert/tls.key \
                --ovn-nb-db-ssl-cert=/ovn-cert/tls.crt \
                --ovn-nb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt \
                --ovn-nb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off" \
                run_nb_ovsdb
        else
            # either we need to initialize a new cluster or wait for master to create it
            if [[ "${K8S_NODE_IP}" == "${MASTER_IP}" ]]; then
                exec /usr/share/ovn/scripts/ovn-ctl \
                    --db-nb-cluster-local-port=${OVN_NB_RAFT_PORT} \
                    --db-nb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
                    --no-monitor \
                    --db-nb-cluster-local-proto=ssl \
                    --ovn-nb-db-ssl-key=/ovn-cert/tls.key \
                    --ovn-nb-db-ssl-cert=/ovn-cert/tls.crt \
                    --ovn-nb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt \
                    --ovn-nb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off" \
                    run_nb_ovsdb
            else
                echo "Joining the nbdb cluster with init_ip=${init_ip}..."
                exec /usr/share/ovn/scripts/ovn-ctl \
                    --db-nb-cluster-local-port=${OVN_NB_RAFT_PORT} \
                    --db-nb-cluster-remote-port=${OVN_NB_RAFT_PORT} \
                    --db-nb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
                    --db-nb-cluster-remote-addr=${init_ip} \
                    --no-monitor \
                    --db-nb-cluster-local-proto=ssl \
                    --db-nb-cluster-remote-proto=ssl \
                    --ovn-nb-db-ssl-key=/ovn-cert/tls.key \
                    --ovn-nb-db-ssl-cert=/ovn-cert/tls.crt \
                    --ovn-nb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt \
                    --ovn-nb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off" \
                    run_nb_ovsdb
            fi
        fi
    else
        exec /usr/share/ovn/scripts/ovn-ctl \
            --db-nb-cluster-local-port=${OVN_NB_RAFT_PORT} \
            --db-nb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
            --no-monitor \
            --db-nb-cluster-local-proto=ssl \
            --ovn-nb-db-ssl-key=/ovn-cert/tls.key \
            --ovn-nb-db-ssl-cert=/ovn-cert/tls.crt \
            --ovn-nb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt \
            --ovn-nb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off" \
            run_nb_ovsdb
    fi
    
    run-nbdb-postStart

}

run-nbdb-postStart() {
    set -x
    MASTER_IP="${OVN_MASTER_IP}"
    if [[ "${K8S_NODE_IP}" == "${MASTER_IP}" ]]; then
        echo "$(date -Iseconds) - nbdb - postStart - waiting for master to be selected"

        # set the connection and disable inactivity probe
        retries=0
        while ! ovn-nbctl --no-leader-only -t 5 set-connection pssl:${OVN_NB_PORT}${LISTEN_DUAL_STACK} -- set connection . inactivity_probe=60000; do
            ((retries += 1))
            if [[ "${retries}" -gt 40 ]]; then
                echo "$(date -Iseconds) - ERROR RESTARTING - nbdb - too many failed ovn-nbctl attempts, giving up"
                exit 1
            fi
            sleep 2
        done

        # Upgrade the db if required.
        DB_SCHEMA="/usr/share/ovn/ovn-nb.ovsschema"
        DB_SERVER="unix:/var/run/ovn/ovnnb_db.sock"
        schema_name=$(ovsdb-tool schema-name $DB_SCHEMA)
        db_version=$(ovsdb-client -t 10 get-schema-version "$DB_SERVER" "$schema_name")
        target_version=$(ovsdb-tool schema-version "$DB_SCHEMA")

        if ovsdb-tool compare-versions "$db_version" == "$target_version"; then
            :
        elif ovsdb-tool compare-versions "$db_version" ">" "$target_version"; then
            echo "Database $schema_name has newer schema version ($db_version) than our local schema ($target_version), possibly an upgrade is partially complete?"
        else
            echo "Upgrading database $schema_name from schema version $db_version to $target_version"
            ovsdb-client -t 30 convert "$DB_SERVER" "$DB_SCHEMA"
        fi
    fi

    #configure northd_probe_interval
    OVN_NB_CTL="ovn-nbctl -p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt \
                --db "${OVN_NB_DB_LIST}""
    northd_probe_interval=${OVN_NORTHD_PROBE_INTERVAL:-5000}
    echo "Setting northd probe interval to ${northd_probe_interval} ms"
    retries=0
    current_probe_interval=0
    while [[ "${retries}" -lt 10 ]]; do
        current_probe_interval=$(${OVN_NB_CTL} --if-exists get NB_GLOBAL . options:northd_probe_interval)
        if [[ $? == 0 ]]; then
            current_probe_interval=$(echo ${current_probe_interval} | tr -d '\"')
            break
        else
            sleep 2
            ((retries += 1))
        fi
    done

    if [[ "${current_probe_interval}" != "${northd_probe_interval}" ]]; then
        retries=0
        while [[ "${retries}" -lt 10 ]]; do
            ${OVN_NB_CTL} set NB_GLOBAL . options:northd_probe_interval=${northd_probe_interval}
            if [[ $? != 0 ]]; then
                echo "Failed to set northd probe interval to ${northd_probe_interval}. retrying....."
                sleep 2
                ((retries += 1))
            else
                echo "Successfully set northd probe interval to ${northd_probe_interval} ms"
                break
            fi
        done
    fi

    #configure NB RAFT election timers
    election_timer="${OVN_NB_RAFT_ELECTION_TIMER}"
    echo "Setting nb-db raft election timer to ${election_timer} ms"
    retries=0
    while current_election_timer=$(ovs-appctl -t /var/run/ovn/ovnnb_db.ctl cluster/status OVN_Northbound 2>/dev/null |
        grep -oP '(?<=Election timer:\s)[[:digit:]]+'); do
        if [[ -z "${current_election_timer}" ]]; then
            ((retries += 1))
            if [[ "${retries}" -gt 10 ]]; then
                echo "Failed to get current nb-db raft election timer value after multiple attempts. Exiting..."
                exit 1
            fi
            sleep 2
        else
            break
        fi
    done

    if [[ ${election_timer} -ne ${current_election_timer} ]]; then
        retries=0
        while is_candidate=$(ovs-appctl -t /var/run/ovn/ovnnb_db.ctl cluster/status OVN_Northbound 2>/dev/null |
            grep "Role: candidate"); do
            if [[ ! -z "${is_candidate}" ]]; then
                ((retries += 1))
                if [[ "${retries}" -gt 10 ]]; then
                    echo "Cluster node (nb-db raft) is in candidate role for prolonged time. Continuing..."
                fi
                sleep 2
            else
                break
            fi
        done

        is_leader=$(ovs-appctl -t /var/run/ovn/ovnnb_db.ctl cluster/status OVN_Northbound 2>/dev/null |
            grep "Role: leader")
        if [[ ! -z "${is_leader}" ]]; then
            while [[ ${current_election_timer} != ${election_timer} ]]; do
                max_election_timer=$((${current_election_timer} * 2))
                if [[ ${election_timer} -le ${max_election_timer} ]]; then
                    if ! ovs-appctl -t /var/run/ovn/ovnnb_db.ctl cluster/change-election-timer OVN_Northbound ${election_timer}; then
                        echo "Failed to set nb-db raft election timer ${election_timer}. Exiting..."
                        exit 2
                    fi
                    current_election_timer=${election_timer}
                else
                    if ! ovs-appctl -t /var/run/ovn/ovnnb_db.ctl cluster/change-election-timer OVN_Northbound ${max_election_timer}; then
                        echo "Failed to set nb-db raft election timer ${max_election_timer}. Exiting..."
                        exit 2
                    fi
                    current_election_timer=${max_election_timer}
                fi
            done
        fi
    fi
}

run-nbdb-readinessProbe() {

    set -xe
    /usr/bin/ovn-appctl -t /var/run/ovn/ovnnb_db.ctl --timeout=3 cluster/status OVN_Northbound 2>/dev/null | grep ${K8S_NODE_IP} | grep -v Address -q
}

run-nbdb-preStop() {
    /usr/bin/ovn-appctl -t /var/run/ovn/ovnnb_db.ctl exit
}


run-kube-rbac-proxy() {
    set -euo pipefail
    TLS_PK=/etc/pki/tls/metrics-cert/tls.key
    TLS_CERT=/etc/pki/tls/metrics-cert/tls.crt
    # As the secret mount is optional we must wait for the files to be present.
    # The service is created in monitor.yaml and this is created in sdn.yaml.
    # If it isn't created there is probably an issue so we want to crashloop.
    retries=0
    while [[ "${retries}" -lt 100 ]]; do
        TS=$(
            curl \
                -s \
                --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
                -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
                "https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/namespaces/ovn-kubernetes/services/ovnkube-master" |
                python -c 'import json,sys; print(json.load(sys.stdin)["metadata"]["creationTimestamp"])' 2>/dev/null || true
        ) || :
        if [ -n "${TS}" ]; then
            break
        fi
        ((retries += 1))
        echo $(date -Iseconds) INFO: Failed to get ovnkube-master service from API. Retry "${retries}"/100 1>&2
        sleep 20
    done
    if [ "${retries}" -ge 20 ]; then
        echo $(date -Iseconds) FATAL: Unable to get ovnkube-master service from API.
        exit 1
    fi

    TS=$(date -d "${TS}" +%s)
    WARN_TS=$((${TS} + $((20 * 60))))
    HAS_LOGGED_INFO=0

    log_missing_certs() {
        CUR_TS=$(date +%s)
        if [[ "${CUR_TS}" -gt "WARN_TS" ]]; then
            echo $(date -Iseconds) WARN: ovn-master-metrics-cert not mounted after 20 minutes.
        elif [[ "${HAS_LOGGED_INFO}" -eq 0 ]]; then
            echo $(date -Iseconds) INFO: ovn-master-metrics-cert not mounted. Waiting 20 minutes.
            HAS_LOGGED_INFO=1
        fi
    }
    while [[ ! -f "${TLS_PK}" || ! -f "${TLS_CERT}" ]]; do
        log_missing_certs
        sleep 5
    done

    exec /usr/bin/kube-rbac-proxy \
        --logtostderr \
        --secure-listen-address=:9102 \
        --tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 \
        --upstream=http://127.0.0.1:29102/ \
        --tls-private-key-file=${TLS_PK} \
        --tls-cert-file=${TLS_CERT}

}

# checks if a db pod is part of a current cluster
db_part_of_cluster() {
    local pod=${1}
    local db=${2}
    local port=${3}
    echo "Checking if ${pod} is part of cluster"
    # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed.
    init_ip=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} ${pod} -o=jsonpath='{.status.podIP}')
    if [[ $? != 0 ]]; then
        echo "Unable to get ${pod} ip "
        return 1
    fi
    echo "Found ${pod} ip: $init_ip"
    init_ip=$(bracketify $init_ip)
    target=$(ovn-${db}ctl --timeout=5 --db=${transport}:${init_ip}:${port} ${ovndb_ctl_ssl_opts} \
        --data=bare --no-headings --columns=target list connection)
    if [[ "${target}" != "p${transport}:${port}${ovn_raft_conn_ip_url_suffix}" ]]; then
        echo "Unable to check correct target ${target} "
        return 1
    fi
    echo "${pod} is part of cluster"
    return 0
}
# end of db_part_of_cluster

# Checks if cluster has already been initialized.
# If not it returns false and sets init_ip to MASTER_IP
cluster_exists() {
    local db=${1}
    local port=${2}
    # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed.
    db_pods=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} -o=jsonpath='{.items[*].metadata.name}' | egrep -o 'ovnkube-master-\w+' | grep -v "metrics")

    for db_pod in $db_pods; do
        if db_part_of_cluster $db_pod $db $port; then
            echo "${db_pod} is part of current cluster with ip: ${init_ip}!"
            return 0
        fi
    done
    # if we get here  there is no cluster, set init_ip and get out
    init_ip=$(bracketify $MASTER_IP)
    return 1
}
# end of cluster_exists()

run-sbdb() {
    set -x
    if [[ -f /env/_master ]]; then
        set -o allexport
        source /env/_master
        set +o allexport
    fi
    

    # initialize variables
    ovn_kubernetes_namespace=openshift-ovn-kubernetes
    ovndb_ctl_ssl_opts="-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt"
    transport="ssl"
    ovn_raft_conn_ip_url_suffix=""
    if [[ "${K8S_NODE_IP}" == *":"* ]]; then
        ovn_raft_conn_ip_url_suffix=":[::]"
    fi
    db="sb"
    db_port="${OVN_SB_PORT}"
    ovn_db_file="/etc/ovn/ovn${db}_db.db"

    MASTER_IP="${OVN_MASTER_IP}"
    echo "$(date -Iseconds) - starting sbdb  MASTER_IP=${MASTER_IP}"
    initial_raft_create=true
    initialize="false"

    if [[ ! -e ${ovn_db_file} ]]; then
        initialize="true"
    fi

    if [[ "${initialize}" == "true" ]]; then
        # check to see if a cluster already exists. If it does, just join it.
        counter=0
        cluster_found=false
        while [ $counter -lt 5 ]; do
            if cluster_exists ${db} ${db_port}; then
                cluster_found=true
                break
            fi
            sleep 1
            counter=$((counter + 1))
        done

        if ${cluster_found}; then
            echo "Cluster already exists for DB: ${db}"
            initial_raft_create=false
            # join existing cluster
            exec /usr/share/ovn/scripts/ovn-ctl \
                --db-sb-cluster-local-port=${OVN_SB_RAFT_PORT} \
                --db-sb-cluster-remote-port=${OVN_SB_RAFT_PORT} \
                --db-sb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
                --db-sb-cluster-remote-addr=${init_ip} \
                --no-monitor \
                --db-sb-cluster-local-proto=ssl \
                --db-sb-cluster-remote-proto=ssl \
                --ovn-sb-db-ssl-key=/ovn-cert/tls.key \
                --ovn-sb-db-ssl-cert=/ovn-cert/tls.crt \
                --ovn-sb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt \
                --ovn-sb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off" \
                run_sb_ovsdb
        else
            # either we need to initialize a new cluster or wait for master to create it
            if [[ "${K8S_NODE_IP}" == "${MASTER_IP}" ]]; then
                exec /usr/share/ovn/scripts/ovn-ctl \
                    --db-sb-cluster-local-port=${OVN_SB_RAFT_PORT} \
                    --db-sb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
                    --no-monitor \
                    --db-sb-cluster-local-proto=ssl \
                    --ovn-sb-db-ssl-key=/ovn-cert/tls.key \
                    --ovn-sb-db-ssl-cert=/ovn-cert/tls.crt \
                    --ovn-sb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt \
                    --ovn-sb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off" \
                    run_sb_ovsdb
            else
                exec /usr/share/ovn/scripts/ovn-ctl \
                    --db-sb-cluster-local-port=${OVN_SB_RAFT_PORT} \
                    --db-sb-cluster-remote-port=${OVN_SB_RAFT_PORT} \
                    --db-sb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
                    --db-sb-cluster-remote-addr=${init_ip} \
                    --no-monitor \
                    --db-sb-cluster-local-proto=ssl \
                    --db-sb-cluster-remote-proto=ssl \
                    --ovn-sb-db-ssl-key=/ovn-cert/tls.key \
                    --ovn-sb-db-ssl-cert=/ovn-cert/tls.crt \
                    --ovn-sb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt \
                    --ovn-sb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off" \
                    run_sb_ovsdb
            fi
        fi
    else
        exec /usr/share/ovn/scripts/ovn-ctl \
            --db-sb-cluster-local-port=${OVN_SB_RAFT_PORT} \
            --db-sb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
            --no-monitor \
            --db-sb-cluster-local-proto=ssl \
            --ovn-sb-db-ssl-key=/ovn-cert/tls.key \
            --ovn-sb-db-ssl-cert=/ovn-cert/tls.crt \
            --ovn-sb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt \
            --ovn-sb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off" \
            run_sb_ovsdb
    fi
    
    run-sbdb-postStart

}

run-sbdb-postStart() {
    set -x
    MASTER_IP="${OVN_MASTER_IP}"
    if [[ "${K8S_NODE_IP}" == "${MASTER_IP}" ]]; then
        echo "$(date -Iseconds) - sdb - postStart - waiting for master to be selected"

        # set the connection and disable inactivity probe
        retries=0
        while ! ovn-sbctl --no-leader-only -t 5 set-connection pssl:${OVN_SB_PORT}${LISTEN_DUAL_STACK} -- set connection . inactivity_probe=60000; do
            ((retries += 1))
            if [[ "${retries}" -gt 40 ]]; then
                echo "$(date -Iseconds) - ERROR RESTARTING - sbdb - too many failed ovn-sbctl attempts, giving up"
                exit 1
            fi
            sleep 2
        done

        # Upgrade the db if required.
        DB_SCHEMA="/usr/share/ovn/ovn-sb.ovsschema"
        DB_SERVER="unix:/var/run/ovn/ovnsb_db.sock"
        schema_name=$(ovsdb-tool schema-name $DB_SCHEMA)
        db_version=$(ovsdb-client -t 10 get-schema-version "$DB_SERVER" "$schema_name")
        target_version=$(ovsdb-tool schema-version "$DB_SCHEMA")

        if ovsdb-tool compare-versions "$db_version" == "$target_version"; then
            :
        elif ovsdb-tool compare-versions "$db_version" ">" "$target_version"; then
            echo "Database $schema_name has newer schema version ($db_version) than our local schema ($target_version), possibly an upgrade is partially complete?"
        else
            echo "Upgrading database $schema_name from schema version $db_version to $target_version"
            ovsdb-client -t 30 convert "$DB_SERVER" "$DB_SCHEMA"
        fi
    fi

    election_timer="${OVN_SB_RAFT_ELECTION_TIMER}"
    echo "Setting sb-db raft election timer to ${election_timer} ms"
    retries=0
    while current_election_timer=$(ovs-appctl -t /var/run/ovn/ovnsb_db.ctl cluster/status OVN_Southbound 2>/dev/null |
        grep -oP '(?<=Election timer:\s)[[:digit:]]+'); do
        if [[ -z "${current_election_timer}" ]]; then
            ((retries += 1))
            if [[ "${retries}" -gt 10 ]]; then
                echo "Failed to get current sb-db raft election timer value after multiple attempts. Exiting..."
                exit 1
            fi
            sleep 2
        else
            break
        fi
    done

    if [[ ${election_timer} -ne ${current_election_timer} ]]; then
        retries=0
        while is_candidate=$(ovs-appctl -t /var/run/ovn/ovnsb_db.ctl cluster/status OVN_Southbound 2>/dev/null |
            grep "Role: candidate"); do
            if [[ ! -z "${is_candidate}" ]]; then
                ((retries += 1))
                if [[ "${retries}" -gt 10 ]]; then
                    echo "Cluster node (sb-db raft) is in candidate role for prolonged time. Continuing..."
                fi
                sleep 2
            else
                break
            fi
        done

        is_leader=$(ovs-appctl -t /var/run/ovn/ovnsb_db.ctl cluster/status OVN_Southbound 2>/dev/null |
            grep "Role: leader")
        if [[ ! -z "${is_leader}" ]]; then
            while [[ ${current_election_timer} != ${election_timer} ]]; do
                max_election_timer=$((${current_election_timer} * 2))
                if [[ ${election_timer} -le ${max_election_timer} ]]; then
                    if ! ovs-appctl -t /var/run/ovn/ovnsb_db.ctl cluster/change-election-timer OVN_Southbound ${election_timer}; then
                        echo "Failed to set sb-db raft election timer ${election_timer}. Exiting..."
                        exit 2
                    fi
                    current_election_timer=${election_timer}
                else
                    if ! ovs-appctl -t /var/run/ovn/ovnsb_db.ctl cluster/change-election-timer OVN_Southbound ${max_election_timer}; then
                        echo "Failed to set sb-db raft election timer ${max_election_timer}. Exiting..."
                        exit 2
                    fi
                    current_election_timer=${max_election_timer}
                fi
            done
        fi
    fi

}

run-sbdb-preStop() {
    /usr/bin/ovn-appctl -t /var/run/ovn/ovnsb_db.ctl exit
    echo "done!"
}

run-sbdb-readinessProbe() {

    set -xe
    /usr/bin/ovn-appctl -t /var/run/ovn/ovnsb_db.ctl --timeout=3 cluster/status OVN_Southbound 2>/dev/null | grep ${K8S_NODE_IP} | grep -v Address -q
}

run-ovn-dbchecker() {
    set -xe
    if [[ -f "/env/_master" ]]; then
        set -o allexport
        source "/env/_master"
        set +o allexport
    fi

    echo "I$(date "+%m%d %H:%M:%S.%N") - ovn-dbchecker - start ovn-dbchecker"
    exec /usr/bin/ovndbchecker \
        --config-file=/run/ovnkube-config/ovnkube.conf \
        --loglevel "${OVN_KUBE_LOG_LEVEL}" \
        --sb-address "${OVN_SB_DB_LIST}" \
        --sb-client-privkey /ovn-cert/tls.key \
        --sb-client-cert /ovn-cert/tls.crt \
        --sb-client-cacert /ovn-ca/ca-bundle.crt \
        --sb-cert-common-name "${OVN_CERT_CN}" \
        --nb-address "${OVN_NB_DB_LIST}" \
        --nb-client-privkey /ovn-cert/tls.key \
        --nb-client-cert /ovn-cert/tls.crt \
        --nb-client-cacert /ovn-ca/ca-bundle.crt \
        --nb-cert-common-name "${OVN_CERT_CN}"

}

run-ovnkube-master() {
    set -xe
    if [[ -f "/env/_master" ]]; then
        set -o allexport
        source "/env/_master"
        set +o allexport
    fi
    gateway_mode_flags=
    # Check to see if ovs is provided by the node. This is only for upgrade from 4.5->4.6 or
    # openshift-sdn to ovn-kube conversion
    if grep -q OVNKubernetes /etc/systemd/system/ovs-configuration.service; then
        gateway_mode_flags="--gateway-mode local --gateway-interface br-ex"
    else
        gateway_mode_flags="--gateway-mode local --gateway-interface none"
    fi

    # start nbctl daemon for caching
    echo "I$(date "+%m%d %H:%M:%S.%N") - ovnkube-master - start nbctl daemon for caching"
    export OVN_NB_DAEMON=$(ovn-nbctl --pidfile=/var/run/ovn/ovn-nbctl.pid \
        --detach \
        -p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt \
        --db "${OVN_NB_DB_LIST}")

    # REMOVEME once OVN path for control socket is fixed (right now uses /var/run/openvswitch)
    ln -sf $OVN_NB_DAEMON /var/run/ovn/ || true

    echo "I$(date "+%m%d %H:%M:%S.%N") - ovnkube-master - start ovnkube --init-master ${K8S_NODE}"
    exec /usr/bin/ovnkube \
        --init-master "${K8S_NODE}" \
        --config-file=/run/ovnkube-config/ovnkube.conf \
        --ovn-empty-lb-events \
        --loglevel "${OVN_KUBE_LOG_LEVEL}" \
        --metrics-bind-address "127.0.0.1:29102" \
        ${gateway_mode_flags} \
        --sb-address "${OVN_SB_DB_LIST}" \
        --sb-client-privkey /ovn-cert/tls.key \
        --sb-client-cert /ovn-cert/tls.crt \
        --sb-client-cacert /ovn-ca/ca-bundle.crt \
        --sb-cert-common-name "${OVN_CERT_CN}" \
        --nb-address "${OVN_NB_DB_LIST}" \
        --nb-client-privkey /ovn-cert/tls.key \
        --nb-client-cert /ovn-cert/tls.crt \
        --nb-client-cacert /ovn-ca/ca-bundle.crt \
        --nbctl-daemon-mode \
        --nb-cert-common-name "${OVN_CERT_CN}" \
        --enable-multicast
}

run-ovnkube-master-preStop() {
    kill $(cat /var/run/ovn/ovn-nbctl.pid) && unset OVN_NB_DAEMON

}

############ Main ################
set -xe
if [[ -f "/env/_master" ]]; then
    set -o allexport
    source "/env/_master"
    set +o allexport
fi

echo "================== ovnkube-master-cno.sh ================"

echo "==================== command: ${cmd} ===================="

case ${cmd} in
"run-northd")
    run-northd
    ;;
"run-nbdb")
    run-nbdb
    ;;
"run-ovn-dbchecker")
    run-ovn-dbchecker
    ;;
"run-nbdb-postStart")
    run-nbdb-postStart
    ;;
"run-ovnkube-master-preStop")
    run-ovnkube-master-preStop
    ;;
"run-ovnkube-master")
    run-ovnkube-master
    ;;
"run-sbdb")
    run-sbdb
    ;;
"run-sbdb-preStop")
    run-sbdb-preStop
    ;;
"run-sbdb-postStart")
    run-sbdb-postStart
    ;;
"run-nbdb-preStop")
    run-nbdb-preStop
    ;;
"run-sbdb-readinessProbe")
    run-sbdb-readinessProbe
    ;;
"run-nbdb-readinessProbe")
    run-nbdb-readinessProbe
    ;;
"run-kube-rbac-proxy")
    run-kube-rbac-proxy
    ;;
*)
    echo "invalid command ${cmd}"
    echo "valid commands: run-ovn-northd run-ovn-dbchecker " \
        "run-nbdb run-nbdb-postStart run-kube-rbac-proxy run-nbdb-readinessProbe " \ 
    "run-sbdb-readinessProbe run-nbdb-preStop run-sbdb-preStop run-sbdb run-sbdb-postStart"
    exit 0
    ;;
esac

exit 0
