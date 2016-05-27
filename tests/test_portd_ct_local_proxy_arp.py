#!/usr/bin/env python

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

import pytest
import re
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch import *


# Topology definition
topoDict = {"topoExecution": 1000,
            "topoTarget": "dut01",
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}


def enterBashShell(dut):
    devIntReturn = dut.DeviceInteract(command="start-shell")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Failed to enter bash shell"
    return True


def enterSWNameSpace(dut):
    # Enter Bash Shell
    if(enterBashShell(dut) is False):
        return False

    cmd = "ip netns exec swns bash"
    devIntReturn = dut.DeviceInteract(command=cmd)
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Failed to enter Software namespace"

    return True


def LocalProxyARPonL3PortTest(dut01):
    if (enterSWNameSpace(dut01) is False):
        return False

    # Routing should be enabled by default
    out = dut01.DeviceInteract(command="sysctl net.ipv4.ip_forward")
    ip_forward_state = out.get('buffer')
    assert 'net.ipv4.ip_forward = 1' in ip_forward_state, "Failed to verify"\
        "ip forwarding is enabled by default"

    # Local Proxy ARP should be disabled by default
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp_pvlan = 0' in local_proxy_arp_state, "Failed to "\
        "verify Local Proxy ARP is disabled by default in kernel via sysctl"

    dut01.DeviceInteract(command="ovs-vsctl add-vrf-port vrf_default 1")
    dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set port 1 \
                                  other_config:local_proxy_arp_enabled=true")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp_pvlan = 1' in local_proxy_arp_state, "Failed to "\
        "verify Local Proxy ARP is enabled on L3 port in kernel via sysctl"

    # Disable Local Proxy ARP on L3 port
    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set port 1 \
                                  other_config:local_proxy_arp_enabled=false")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp_pvlan = 0' in local_proxy_arp_state, "Failed to "\
        "verify Local Proxy ARP is disabled on L3 port in kernel via sysctl"

    # Clear column
    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set port 1 \
                                       other_config:local_proxy_arp_enabled=true")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp_pvlan = 1' in local_proxy_arp_state, "Failed to "\
        "verify Local proxy ARP is enabled on L3 port in kernel via sysctl"

    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl clear \
                                        port 1 other_config")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp_pvlan = 0' in local_proxy_arp_state, "Failed to "\
        "verify Local Proxy ARP is disabled on L3 port in kernel via sysctl"
    return True


def LocalProxyARPonL2PortTest(dut01):
    # Try enable Local Proxy ARP on a L2 port
    out = dut01.DeviceInteract(command="ovs-vsctl add-port bridge_normal 2")
    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set port 1 \
                                      other_config:local_proxy_arp_enabled=true")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.2.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.2.proxy_arp_pvlan = 0' in local_proxy_arp_state, "Failed to "\
        "verify Local Proxy ARP cannot be enabled on L2 port in kernel via sysctl"
    return True


def LocalProxyARPonSplitParentInterfaceTest(dut01):

    # enable Local Proxy ARP on a non-split parent interface
    dut01.DeviceInteract(command="ovs-vsctl add-vrf-port vrf_default 54")
    out = dut01.DeviceInteract(command="ovs-vsctl list Port 54")
    port_table = out.get('buffer')
    assert 'no row \"54\" in table Port' not in port_table, "Port Table "\
        "entry not present for parent interface."
    dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set port 54 \
                                    other_config:local_proxy_arp_enabled=true")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.54.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.54.proxy_arp_pvlan = 1' in local_proxy_arp_state, "Failed to "\
        "verify Local Proxy ARP is Enabled on a non split parent interface in "\
        "kernel via sysctl"

    # Local Proxy ARP should be disabled on a split interface.
    dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set Interface 54 \
                                        user_config:lane_split=split")
    dut01.DeviceInteract(command="/usr/bin/ovs-vsctl del-vrf-port 54")
    out = dut01.DeviceInteract(command="ovs-vsctl list Port 54")
    port_table = out.get('buffer')
    assert 'no row \"54\" in table Port' in port_table, "Port Table entry "\
        "still present for parent interface."
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.54.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.54.proxy_arp_pvlan = 0' in local_proxy_arp_state, "Failed to "\
        "verify Local Proxy ARP is Disabled on a split parent interface in "\
        "kernel via sysctl"

    return True


def LocalProxyARPonSplitChildInterfaceTest(dut01):
    # Proxy ARP on a split child interface
    out = dut01.DeviceInteract(command="ovs-vsctl add-vrf-port vrf_default 53")
    port_table = out.get('buffer')
    assert 'no row \"53\" in table Port' not in port_table, "Port Table entry"\
        " not present for parent interface."
    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set Interface 53 \
                                         user_config:lane_split=split")
    dut01.DeviceInteract(command="/usr/bin/ovs-vsctl del-vrf-port 53")
    out = dut01.DeviceInteract(command="ovs-vsctl list Port 53")
    port_table = out.get('buffer')
    assert 'no row \"53\" in table Port' in port_table, "Port Table entry" \
        " still present for parent interface."

    dut01.DeviceInteract(command="ovs-vsctl add-vrf-port vrf_default 53-1")

    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set port 53-1 \
                               other_config:local_proxy_arp_enabled=true")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.53-1.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.53-1.proxy_arp_pvlan = 1' in local_proxy_arp_state, "Failed to "\
        "verify Local Proxy ARP is Enabled on child interface in kernel via sysctl"\

    # Disable Split interface.
    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl clear Interface 53 \
                                        user_config")
    dut01.DeviceInteract(command="/usr/bin/ovs-vsctl del-vrf-port 53-1")
    dut01.DeviceInteract(command="ovs-vsctl add-vrf-port vrf_default 53")
    out = dut01.DeviceInteract(command="ovs-vsctl list Port 53")
    port_table = out.get('buffer')
    assert 'no row \"53\" in table Port' not in port_table, "Port Table entry"\
        "not present for parent interface."
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.53-1.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.53-1.proxy_arp_pvlan = 0' in local_proxy_arp_state, "Failed to "\
        "verify in kernel via sysctl that Local Proxy ARP is disabled on child "\
        "interface when parent interface is reset to no split."

    return True


def LocalProxyARPonVLANInterfaceTest(dut01):
    # Interface table does not have a vlan interface entry by default.
    # so creating an entry by entering the context.
    dut01.DeviceInteract(command="vtysh")
    dut01.DeviceInteract(command="config terminal")
    dut01.DeviceInteract(command="interface vlan 3")
    dut01.DeviceInteract(command="end")
    dut01.DeviceInteract(command="exit")

    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set port vlan3 \
                                      other_config:local_proxy_arp_enabled=true")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.vlan3.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.vlan3.proxy_arp_pvlan = 1' in local_proxy_arp_state, "Failed to"\
        " verify Local Proxy ARP is enabled on vlan interface in kernel via sysctl"

    # Disable local Proxy ARP on VLAN interface
    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set port vlan3 \
                                  other_config:local_proxy_arp_enabled=false")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.vlan3.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.vlan3.proxy_arp_pvlan = 0' in local_proxy_arp_state, "Failed to"\
        " verify Local Proxy ARP is disabled on vlan interface in kernel via sysctl"

    # Clear column
    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl set port vlan3 \
                                       other_config:local_proxy_arp_enabled=true")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.vlan3.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.vlan3.proxy_arp_pvlan = 1' in local_proxy_arp_state, "Failed to"\
        " verify Local Proxy ARP is enabled on vlan interface in kernel via sysctl"

    out = dut01.DeviceInteract(command="/usr/bin/ovs-vsctl clear port \
                                        vlan3 other_config")
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.vlan3.proxy_arp_pvlan")
    local_proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.vlan3.proxy_arp_pvlan = 0' in local_proxy_arp_state, "Failed to"\
        " verify Local Proxy ARP is disabled on vlan interface in kernel via sysctl"

    return True

@pytest.mark.skipif(True, reason="skipped test case due to gate job failures.")
class Test_localproxyarp_feature:
    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_localproxyarp_feature.testObj =\
            testEnviron(topoDict=topoDict, defSwitchContext="vtyShell")
        # Get topology object
        Test_localproxyarp_feature.topoObj = \
            Test_localproxyarp_feature.testObj.topoObjGet()

    def teardown_class(cls):
        Test_localproxyarp_feature.topoObj.terminate_nodes()

    def test_LocalProxyARPOnL3Port(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")

        retValue = LocalProxyARPonL3PortTest(dut01Obj)
        if(retValue):
            LogOutput('info', "Local Proxy ARP on L3 port - passed")
        else:
            LogOutput('error', "Local Proxy ARP on L3 port - failed")

    def test_LocalProxyARPOnL2Port(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")

        retValue = LocalProxyARPonL2PortTest(dut01Obj)
        if(retValue):
            LogOutput('info', "Local Proxy ARP on L2 port - passed")
        else:
            LogOutput('error', "Local Proxy ARP on L2 port - failed")

    def test_LocalProxyARPOnSplitParentPort(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")

        retValue = LocalProxyARPonSplitParentInterfaceTest(dut01Obj)
        if(retValue):
            LogOutput('info', "Local Proxy ARP on split parent interface - passed")
        else:
            LogOutput('error', "Local Proxy ARP on split parent interface - failed")

    def test_LocalProxyARPOnSplitChildPort(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")

        retValue = LocalProxyARPonSplitChildInterfaceTest(dut01Obj)
        if(retValue):
            LogOutput('info', "Local Proxy ARP on split child interface - passed")
        else:
            LogOutput('error', "Local Proxy ARP on split child interface - failed")

    def test_LocalProxyARPOnVLANPort(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")

        retValue = LocalProxyARPonVLANInterfaceTest(dut01Obj)
        if(retValue):
            LogOutput('info', "Local Proxy ARP on VLAN interface - passed")
        else:
            LogOutput('error', "Local Proxy ARP on VLAN interface - failed")
