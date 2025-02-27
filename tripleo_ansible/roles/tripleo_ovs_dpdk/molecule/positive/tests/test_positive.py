# Copyright 2019 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import configparser
import os

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def get_config(host):
    stdout = host.check_output('ovs-vsctl get open_vswitch . other_config')
    content = '[default]\n' + stdout.replace('{', '').replace('}', '').replace(', ', '\n')
    print(content)
    cfg = configparser.RawConfigParser()
    cfg.read_string(content)
    print(dict(cfg['default']))
    return dict(cfg['default'])


def test_positive_dpdk_extra(host):
    other_config = get_config(host)
    dpdk_extra = other_config['dpdk-extra'].replace('"', '')
    assert dpdk_extra == "--iova-mode=va -n 3"


def test_positive_pmd(host):
    other_config = get_config(host)
    dpdk_extra = other_config['pmd-cpu-mask'].replace('"', '')
    assert dpdk_extra == "18000000000000003000000000c00000c"


def test_positive_lcore(host):
    other_config = get_config(host)
    dpdk_extra = other_config['dpdk-lcore-mask'].replace('"', '')
    assert dpdk_extra == "3000003"


def test_positive_socket_mem(host):
    other_config = get_config(host)
    socket_mem = other_config['dpdk-socket-mem'].replace('"', '')
    socket_limit = other_config['dpdk-socket-limit'].replace('"', '')
    assert socket_mem == "1024,1024"
    assert socket_limit == "1024,1024"


def test_positive_validator_threads(host):
    other_config = get_config(host)
    dpdk_extra = other_config['n-revalidator-threads'].replace('"', '')
    assert dpdk_extra == "2"


def test_positive_handler_threads(host):
    other_config = get_config(host)
    dpdk_extra = other_config['n-handler-threads'].replace('"', '')
    assert dpdk_extra == "2"


def test_positive_emc_prob(host):
    other_config = get_config(host)
    dpdk_extra = other_config['emc-insert-inv-prob'].replace('"', '')
    assert dpdk_extra == "0"


def test_positive_enable_tso(host):
    other_config = get_config(host)
    tso_enabled = other_config['userspace-tso-enable'].replace('"', '')
    assert tso_enabled == "true"


def test_positive_pmd_load_threshold(host):
    other_config = get_config(host)
    pmd_load_threshold = other_config['pmd-auto-lb-load-threshold'].replace('"', '')
    assert pmd_load_threshold == "50"


def test_positive_pmd_improvement_threshold(host):
    other_config = get_config(host)
    pmd_improvement_threshold = other_config['pmd-auto-lb-improvement-threshold'].replace('"', '')
    assert pmd_improvement_threshold == "10"


def test_positive_pmd_rebal_interval(host):
    other_config = get_config(host)
    pmd_rebal_interval = other_config['pmd-auto-lb-rebal-interval'].replace('"', '')
    assert pmd_rebal_interval == "5"
