# -*- coding: utf-8 -*-

# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

import layer3_common as lib
from time import sleep
from pytest import mark

TOPOLOGY = """
# +-------+     +--------+     +-------+
# |  hs1  <----->  ops1  <----->  hs2  |
# +-------+     +--------+     +-------+

# Nodes
[type=openswitch] ops1
[type=host] hs1
[type=host] hs2

# Links
hs1:eth0 -- ops1:if01
ops1:if02 -- hs2:eth0
"""


@mark.timeout(500)
def test_slow_routing_direct_connected(topology, step):
    """
    Verify slow path routing for directly connected hosts.
    """
    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    # ----------Configure Switches and Hosts----------

    step('Configure switch and host ports')
    lib.switch_cfg_iface(ops1, 'if01', '192.168.1.1/24', '2000::1/120')
    lib.switch_cfg_iface(ops1, 'if02', '192.168.2.1/24', '2002::1/120')
    sleep(10)

    lib.host_cfg_iface(hs1, 'eth0', '192.168.1.2/24', '2000::2/120')
    lib.host_cfg_iface(hs2, 'eth0', '192.168.2.2/24', '2002::2/120')

    lib.host_add_route(hs1, '192.168.2.0/24', '192.168.1.1')
    lib.host_add_route(hs2, '192.168.1.0/24', '192.168.2.1')
    lib.host_add_route(hs1, '2002::0/120', '2000::1')
    lib.host_add_route(hs2, '2000::0/120', '2002::1')

    # ----------Test IPv4 Ping----------

    step('Test IPv4 Ping')
    lib.host_ping_expect_success(10, hs1, ops1, '192.168.1.1')
    lib.host_ping_expect_success(10, hs2, ops1, '192.168.2.1')
    lib.host_ping_expect_success(10, hs1, hs2, '192.168.2.2')

    # ----------Test IPv6 Ping----------

    step('Test IPv6 Ping')
    lib.host_ping_expect_success(10, hs1, ops1, '2000::1')
    lib.host_ping_expect_success(10, hs2, ops1, '2002::1')
    lib.host_ping_expect_success(10, hs1, hs2, '2002::2')
