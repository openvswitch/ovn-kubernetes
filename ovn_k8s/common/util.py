# Copyright (C) 2016 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import random
import subprocess

import ovs.vlog
from ovn_k8s.common import exceptions
from ovn_k8s.common import variables

vlog = ovs.vlog.Vlog("util")


def call_popen(cmd):
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = child.communicate()
    if child.returncode:
        raise RuntimeError("Fatal error executing %s" % (cmd))
    if len(output) == 0 or output[0] is None:
        output = ""
    else:
        output = output[0].decode("utf8").strip()
    return output


def call_prog(prog, args_list):
    cmd = [prog, "--timeout=5", "-vconsole:off"] + args_list
    return call_popen(cmd)


def ovs_vsctl(*args):
    return call_prog("ovs-vsctl", list(args))


def ovs_ofctl(*args):
    return call_prog("ovs-ofctl", list(args))


def ovn_nbctl(*args):
    args_list = list(args)
    if variables.OVN_NB.startswith("ssl"):
        private_key = "%s=%s" % ("--private-key", variables.NBCTL_PRIVATE_KEY)
        args_list.insert(0, private_key)
        certificate = "%s=%s" % ("--certificate", variables.NBCTL_CERTIFICATE)
        args_list.insert(0, certificate)
        cacert = "%s=%s" % ("--bootstrap-ca-cert", variables.NBCTL_CA_CERT)
        args_list.insert(0, cacert)
    database_option = "%s=%s" % ("--db", variables.OVN_NB)
    args_list.insert(0, database_option)
    return call_prog("ovn-nbctl", args_list)


def generate_mac(prefix="00:00:00"):
    random.seed()
    mac = "%s:%02X:%02X:%02X" % (
        prefix,
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255))
    return mac


def process_stream(data_stream, event_callback):
    try:
        line = next(data_stream)
        if not line:
            return
    except StopIteration:
        raise exceptions.APIServerTimeout()

    try:
        event_callback(json.loads(line))
    except ValueError:
        vlog.warn("Invalid JSON data from response stream:%s" % line)
