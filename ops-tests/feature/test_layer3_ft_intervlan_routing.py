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
# +-------+                        +-------+
# |  hs1  <---+   +--------+   +--->  hs3  |
# +-------+   +--->        <---+   +-------+
#                 |  ops1  |
# +-------+   +--->        <---+   +-------+
# |  hs2  <---+   +--------+   +--->  hs4  |
# +-------+                        +-------+

# Nodes
[type=openswitch] ops1
[type=host] hs1
[type=host] hs2
[type=host] hs3
[type=host] hs4

# Links
ops1:if01 -- hs1:eth0
ops1:if02 -- hs2:eth0
ops1:if03 -- hs3:eth0
ops1:if04 -- hs4:eth0
"""

PING_BYTES = 84


def verify_l3_stats(switch, iface, base_stats, ping_cnt):
    # Retry loop around tx and rx stats.
    for iteration in range(0, 5):
        pass_cases = 0
        stats = switch.libs.vtysh.show_interface(iface)

        rx_packets = stats['rx_l3_ucast_packets']
        tx_packets = stats['tx_l3_ucast_packets']
        rx_bytes = stats['rx_l3_ucast_bytes']
        tx_bytes = stats['tx_l3_ucast_bytes']
        base_rx_packets = base_stats['rx_l3_ucast_packets']
        base_tx_packets = base_stats['tx_l3_ucast_packets']

        if rx_packets < (ping_cnt + base_rx_packets):
            print("Retrying statistic - waiting for rx packets to update")
            sleep(5)
            continue
        pass_cases = pass_cases + 1
        if tx_packets < (ping_cnt + base_tx_packets):
            print("Retrying statistic - waiting for tx packets to update")
            sleep(5)
            continue
        pass_cases = pass_cases + 1
        if rx_bytes < ((ping_cnt + base_rx_packets) * PING_BYTES):
            print("Retrying statistic - waiting for rx bytes to update")
            sleep(5)
            continue
        pass_cases = pass_cases + 1
        if tx_bytes < ((ping_cnt + base_tx_packets) * PING_BYTES):
            print("Retrying statistic - waiting for tx bytes to update")
            sleep(5)
            continue
        pass_cases = pass_cases + 1
        if pass_cases == 4:
            break

    # Verify RX_packets
    assert rx_packets >= (ping_cnt + base_rx_packets), "rx_packets wrong."
    # Verify TX_packets
    assert tx_packets >= (ping_cnt + base_tx_packets), "tx_packets wrong."
    # Verify RX_bytes
    assert rx_bytes >= ((ping_cnt + base_rx_packets) * PING_BYTES), (
        "rx_bytes wrong.")
    # Verify TX_bytes
    assert tx_bytes >= ((ping_cnt + base_tx_packets) * PING_BYTES), (
        "tx_bytes wrong.")


@mark.timeout(1000)
@mark.platform_incompatible(['docker'])
def test_intervlan_routing(topology, step):
    """
    Verify intervlan routing.
    """

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    hs3 = topology.get('hs3')
    hs4 = topology.get('hs4')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None
    assert hs3 is not None
    assert hs4 is not None

    # ----------Configure Switches and Hosts----------

    step('Configure Switches and Hosts')
    lib.switch_add_vlan(ops1, 10)
    lib.switch_add_vlan(ops1, 20)

    lib.switch_add_vlan_port(ops1, 10, 'if01')
    lib.switch_add_vlan_port(ops1, 10, 'if02')
    lib.switch_add_vlan_port(ops1, 20, 'if03')

    lib.switch_cfg_vlan(ops1, 10, '10.0.0.1/24', '1000::1/120')
    lib.switch_cfg_vlan(ops1, 20, '20.0.0.1/24', '2000::1/120')

    lib.switch_cfg_iface(ops1, 'if04', '30.0.0.1/24', '3000::1/120')
    sleep(10)

    lib.host_cfg_iface(hs1, 'eth0', '10.0.0.9/24', '1000::9/120')
    lib.host_cfg_iface(hs2, 'eth0', '10.0.0.10/24', '1000::10/120')
    lib.host_cfg_iface(hs3, 'eth0', '20.0.0.10/24', '2000::10/120')
    lib.host_cfg_iface(hs4, 'eth0', '30.0.0.10/24', '3000::10/120')

    lib.host_add_route(hs1, '0.0.0.0/0', '10.0.0.1')
    lib.host_add_route(hs2, '0.0.0.0/0', '10.0.0.1')
    lib.host_add_route(hs3, '0.0.0.0/0', '20.0.0.1')
    lib.host_add_route(hs4, '0.0.0.0/0', '30.0.0.1')
    lib.host_add_route(hs1, '::/0', '1000::1')
    lib.host_add_route(hs2, '::/0', '1000::1')
    lib.host_add_route(hs3, '::/0', '2000::1')
    lib.host_add_route(hs4, '::/0', '3000::1')

    # ----------Ping after configuring vlan----------

    step('Ping after configuring vlan')
    lib.host_ping_expect_success(10, hs1, hs2, '10.0.0.10')
    lib.host_ping_expect_success(10, hs1, hs3, '20.0.0.10')
    lib.host_ping_expect_success(10, hs1, hs4, '30.0.0.10')
    lib.host_ping_expect_success(10, hs1, hs2, '1000::10')
    lib.host_ping_expect_success(10, hs1, hs3, '2000::10')
    lib.host_ping_expect_success(10, hs1, hs4, '3000::10')

    # ----------Baselining stats on L3 interfaces----------

    step('Baselining L3 stats')
    base_vlan10 = ops1.libs.vtysh.show_interface("vlan10")
    base_vlan20 = ops1.libs.vtysh.show_interface("vlan20")
    base_ip_intf4 = ops1.libs.vtysh.show_ip_interface("if04")
    base_ipv6_intf4 = ops1.libs.vtysh.show_ipv6_interface("if04")

    # ----------Ping host 3 host 4 from host 1----------

    step("Ping host 3 host 4 from host 1")
    hs1.libs.ping.ping(5, '20.0.0.10')
    hs1.libs.ping.ping(5, '2000::10')
    hs1.libs.ping.ping(5, '30.0.0.10')
    hs1.libs.ping.ping(5, '3000::10')

    # ----------Verify L3 statistics on L3 interfaces----------

    step("Verify L3 statistics on L3 interfaces")
    print("Verify interface vlan10 stats")
    verify_l3_stats(ops1, "vlan10", base_vlan10, 20)
    print("Verify interface vlan20 stats")
    verify_l3_stats(ops1, "vlan20", base_vlan20, 10)
    print("Verify ip phy interface stats")
    verify_l3_stats(ops1, "if04", base_ip_intf4, 5)
    print("Verify ipv6 phy interface stats")
    verify_l3_stats(ops1, "if04", base_ipv6_intf4, 5)

    # ----------Remove vlans----------

    step('Remove vlan interfaces')
    lib.switch_remove_interface_vlan(ops1, "10")
    lib.switch_remove_interface_vlan(ops1, "20")

    # ----------Ping after removing vlan----------

    step('Ping after removing vlan')
    lib.host_ping_expect_success(10, hs1, hs2, '10.0.0.10')
    lib.host_ping_expect_failure(10, hs1, hs3, '20.0.0.10')
    lib.host_ping_expect_success(10, hs1, hs2, '1000::10')
    lib.host_ping_expect_failure(10, hs1, hs3, '2000::10')
