#!/usr/bin/env python

# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
#
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
from opstestfw.switch.CLI import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoTarget": "dut01",
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}

intf1 = 1
intf2 = 2
intf3 = 3
intf4 = 4


def execute_command_and_verify_response(switch, command, max_try=1,
                                        wait_time=1, **verify_strs):
    for i in range(max_try):
        returnStructure = switch.DeviceInteract(command=command)
        bufferout = returnStructure.get('buffer')
        passed = True
        if verify_strs is not None:
            for key, value in verify_strs.iteritems():
                if value not in bufferout:
                    passed = False
                    break
        if passed is True:
            break
        else:
            sleep(wait_time)
    if passed is True:
        if i > 0:
            LogOutput('debug', "Passed verify string after "
                      + str(i) + " retries.")
    else:
        LogOutput('info', "Failed verify string after "
                  + str(max_try) + " retries.\nBuffer:\n" + bufferout)

    return passed


    # Test Case 1:
    # Test case checks ascending internal VLAN range to ensure VLANs are
    # allocated in ascending order.
def portd_functionality_tc1(**kwargs):
    switch = kwargs.get('switch', None)

    # CLI equivalent of the APIs/commands used below to configure switch
    '''
    switch(config)#vlan internal range 400 500 ascending
    switch(config)#interface 1
    switch(config-if)#ip address 10.1.1.1/8
    switch(config-if)#exit
    switch(config)#interface 2
    switch(config-if)#ip address 11.1.1.1/8
    switch(config-if)#exit
    '''
    LogOutput('info', "\n\n######## Assigning internal "
              "VLAN range in ascending order ########")
    '''
    Need to set the l3_port_requires_internal_vlan=1 for genericx86_64
    environment to enable internal VLAN on L3 interfaces
    '''
    command = \
        "ovs-vsctl set Subsystem base other_info:"\
        "l3_port_requires_internal_vlan=1"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to modify internal vlan field in Subsystem \
            Table to allow internal VLAN assignment in genericx86-64 \
            environment"
    returnStructure = switch.ConfigVtyShell(enter=True)
    command = "vlan internal range 400 500 ascending"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to assign internal VLAN range \
            in ascending order"
    LogOutput('info', "### Assigning ip address to interface 1 ###")
    returnStructure = InterfaceIpConfig(
        deviceObj=switch,
        interface=1,
        addr="10.1.1.1",
        mask=8,
        config=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot configure ip address on interface %d" % intf1
    LogOutput('info', "### Assigning ip address to interface 2 ###")
    returnStructure = InterfaceIpConfig(
        deviceObj=switch,
        interface=intf2,
        addr="11.1.1.1",
        mask=8,
        config=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot configure ip address on interface %d" % intf2
    returnStructure = switch.VtyshShell(enter=True)
    LogOutput(
        'info',
        "### Verifying internal VLANs assigned to interfaces in the DB ###")
    command = "show vlan internal"
    returnStructure = switch.DeviceInteract(command=command)
    buffer = returnStructure.get('buffer')
    bufferout = buffer.replace("\r", "")
    out = bufferout.split('\n')
    indexval = out.index("Assigned Interfaces:")
    assert '400' in out[indexval + 3] or '400' in out[indexval + 4] and \
        '401' in out[indexval + 3] or '401' in out[indexval + 4], \
        "Unable to verify internal VLAN for interfaces %d and %d  \
            in the DB" % (intf1, intf2)
    returnStructure = switch.VtyshShell(enter=False)
    LogOutput(
        'info',
        "### Verifying internal VLANs assigned to interfaces in the kernel ###"
    )
    command = "ip netns exec swns ip addr show 1"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    out = bufferout.split()
    indexval = out.index("inet")
    assert '10.1.1.1/8' in out[indexval + 1], "Cannot verify kernel \
            ip address on interface %d" % intf1
    command = "ip netns exec swns ip addr show 2"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    out = bufferout.split()
    indexval = out.index("inet")
    assert '11.1.1.1/8' in out[indexval + 1], "Cannot verify kernel \
            ip address on interface %d" % intf2


    # Test Case 2:
    # Test case checks if the default range is being used by portd while
    # assigning new internal VLANs.
def portd_functionality_tc2(**kwargs):
    switch = kwargs.get('switch', None)

    # CLI command equivalent of the APIs/commands used below to configure
    # switch
    '''
    switch(config)#no vlan internal range
    switch(config)#interface 3
    switch(config-if)#ip address 12.1.1.1/8
    switch(config)#exi
    '''
    LogOutput('info', "\n\n######## Removing internal VLAN range ########")
    returnStructure = switch.ConfigVtyShell(enter=True)
    command = "no vlan internal range"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to remove assigned internal VLAN range"
    LogOutput('info', "### Assigning ip address to interface 3 ###")
    returnStructure = InterfaceIpConfig(
        deviceObj=switch,
        interface=intf3,
        addr="12.1.1.1",
        mask=8,
        config=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot configure ip address on interface %d" % intf3
    LogOutput(
        'info',
        "### Verifying default internal VLAN assigned to interface 3"
        " in the DB ###")
    command = "ovs-vsctl get port 3 hw_config:internal_vlan_id"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert '"1024"' in bufferout, "Unable to verify internal VLAN for \
            interface %d in the DB" % intf3
    LogOutput(
        'info',
        "### Verifying default internal VLAN assigned to interface 3"
        " in the kernel ###")
    command = "ip netns exec swns ip addr show 3"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    out = bufferout.split()
    indexval = out.index("inet")
    assert '12.1.1.1/8' in out[indexval + 1], "Cannot verify kernel \
            ip address on interface %d" % intf3


    # Test Case 3:
    # Test case checks descending internal VLAN range to ensure VLANs are
    # allocated in descending order.
def portd_functionality_tc3(**kwargs):
    switch = kwargs.get('switch', None)

    # CLI command equivalent of the APIs/commands used below to configure
    # switch
    '''
    switch(config)#vlan internal range 3000 4000 descending
    switch(config)#interface 4
    switch(config-if)#ip address 13.1.1.1/8
    switch(config-if)#exit
    '''
    LogOutput(
        'info',
        "\n\n######## Assigning internal VLAN range in descending order"
        " ########")
    returnStructure = switch.ConfigVtyShell(enter=True)
    command = "vlan internal range 3000 4000 descending"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to assign internal VLAN range in \
            descending order"
    LogOutput('info', "### Assigning ip address to interface 4 ###")
    returnStructure = InterfaceIpConfig(
        deviceObj=switch,
        interface=intf4,
        addr="13.1.1.1",
        mask=8,
        config=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot configure ip address on interface %d" % intf4
    LogOutput(
        'info',
        "### Verifying internal VLAN assigned to interface 4 in the DB ###")
    command = "ovs-vsctl get port 4 hw_config:internal_vlan_id"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert '"4000"' in bufferout, "Unable to verify internal VLAN range for \
            interface %d in the DB" % intf4
    LogOutput(
        'info',
        "### Verifying internal VLAN assigned to interface 4 in the kernel ###"
    )
    command = "ip netns exec swns ip addr show 4"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    out = bufferout.split()
    indexval = out.index("inet")
    assert '13.1.1.1/8' in out[indexval + 1], "Cannot verify kernel \
            ip address on interface %d" % intf4


    # Test Case 4:
    # Test case checks co-existence of L2 VLANs and internal VLANs.
def portd_functionality_tc4(**kwargs):
    switch = kwargs.get('switch', None)

    # CLI command equivalent of the APIs/commands used below to configure
    # switch
    '''
    switch(config)#vlan internal range 500 600 ascending
    switch(config)#interface 1
    switch(config-if)#no routing
    switch(config-if)#routing
    switch(config-if)#ip address 14.1.1.1/8
    switch(config-if)#exit
    switch(config)#vlan 500     #Should not enter into (config-vlan) prompt
                                #and throw out error
    switch(config)#interface 1
    switch(config-if)#no routing
    switch(config-if)#exit
    switch(config)#vlan 500     #Should be able to enter into (config-vlan)
                                #prompt this time
    switch(config-vlan)#exit
    '''
    LogOutput(
        'info',
        "\n\n######## Assigning same L2 VLAN after configuring L3 internal"
        " VLAN ########")
    LogOutput(
        'info',
        "### Assigning internal VLAN range 500-600 in ascending order ###")
    returnStructure = switch.ConfigVtyShell(enter=True)
    command = "vlan internal range 500 600 ascending"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to assign internal VLAN range in ascending \
            order"
    returnStructure = switch.ConfigVtyShell(enter=True)
    LogOutput('info', "### Deleting L3 configuration on interface 1 ###")
    command = "interface 1"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to enter interface context for interface \
            %d" % intf1
    command = "no routing"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to execute 'no routing' for interface \
            %d" % intf1
    command = "routing"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to execute 'routing' for interface %d" % intf1
    LogOutput('info', "### Assigning ip address to interface 1 ###")
    returnStructure = InterfaceIpConfig(
        deviceObj=switch,
        interface=intf1,
        addr="14.1.1.1",
        mask=8,
        config=True)
    retCode = returnStructure.returnCode()
    bufferout = returnStructure.buffer()
    assert retCode == 0, "Cannot configure ip address on interface %d" % intf1
    LogOutput('info', "### Trying to assign L2 VLAN500 which should fail ###")
    returnStructure = AddVlan(deviceObj=switch, vlanId=500, config=True)
    bufferout = returnStructure.buffer()
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Able to configure L2 VLAN500"
    assert "VLAN500 is used as an internal VLAN. No further configuration" \
        " allowed" in bufferout, "Able to assign L2 VLAN even though \
            internal VLAN was present"
    returnStructure = switch.ConfigVtyShell(enter=True)
    LogOutput('info', "### Deleting L3 configuration on interface 1 ###")
    command = "interface 1"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to enter interface context for interface \
            %d" % intf1
    command = "no routing"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to execute 'no routing' for interface \
            %d" % intf1
    command = "exit"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to exit out of interface context"
    returnStructure = switch.ConfigVtyShell(enter=False)
    LogOutput(
        'info',
        "### Trying to re-assign L2 VLAN500 which should be successful ###")
    returnStructure = AddVlan(deviceObj=switch, vlanId=500, config=True)
    bufferout = returnStructure.buffer()
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to assign L2 VLAN even though internal VLAN \
            was absent"
    command = "ovs-vsctl get vlan VLAN500 name"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    bufferout = returnStructure.get('buffer')
    assert retCode == 0, "Unable to get added L2 VLAN500 information"
    assert '"VLAN500"' in bufferout, "Unable to verify added L2 VLAN500"


    # Test Case 5:
    # Test case checks sequential assignment of internal VLANs when L2 VLANs
    # are present or absent.
def portd_functionality_tc5(**kwargs):
    switch = kwargs.get('switch', None)

    # CLI command equivalent of the APIs/commands used below to configure
    # switch
    '''
    switch(config)#vlan 1000
    switch(config-vlan)#exit
    switch(config)#vlan 1001
    switch(config-vlan)#exit
    switch(config)#vlan internal range 1000 1100 ascending
    switch(config)#interface 1
    switch(config-if)#no routing
    switch(config-if)#routing
    switch(config-if)#ip address 15.1.1.1/8
    switch(config-if)#exit
    switch(config)#no vlan 1001
    switch(config)#interface 2
    switch(config-if)#no routing
    switch(config-if)#routing
    switch(config-if)#ip address 16.1.1.1/8
    switch(config-if)#exit
    '''
    LogOutput(
        'info',
        "\n\n######## Verifying sequential assignment of L3 internal VLAN"
        " when L2 VLAN is present or absent ########")
    LogOutput('info', "### Adding L2 VLAN1000 ###")
    returnStructure = AddVlan(deviceObj=switch, vlanId=1000, config=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to assign L2 VLAN1000"
    LogOutput('info', "### Adding L2 VLAN1001 ###")
    returnStructure = AddVlan(deviceObj=switch, vlanId=1001, config=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to assign L2 VLAN1001"
    returnStructure = switch.ConfigVtyShell(enter=True)
    LogOutput(
        'info',
        "### Assigning internal VLAN range 1000-1100 in ascending order ###")
    command = "vlan internal range 1000 1100 ascending"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to assign internal VLAN range in ascending \
            order"
    LogOutput('info', "### Deleting L3 configuration on interface 1 ###")
    returnStructure = switch.ConfigVtyShell(enter=True)
    command = "interface 1"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to enter interface context for interface \
            %d" % intf1
    command = "no routing"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to execute 'no routing' for interface \
            %d" % intf1
    command = "routing"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to execute 'routing' for interface %d" % intf1
    LogOutput('info', "### Assigning ip address to interface 1 ###")
    returnStructure = InterfaceIpConfig(
        deviceObj=switch,
        interface=intf1,
        addr="15.1.1.1",
        mask=8,
        config=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot configure ip address on interface %d" % intf1
    LogOutput(
        'info',
        "### Verifying internal VLAN assigned to interface 1 in the DB ###")
    command = "ovs-vsctl get port 1 hw_config:internal_vlan_id"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert '"1002"' in bufferout, "Unable to verify internal VLAN for \
            interface %d in the DB" % intf1
    LogOutput('info', "### Deleting L2 VLAN1001 ###")
    returnStructure = AddVlan(deviceObj=switch, vlanId=1001, config=False)
    bufferout = returnStructure.returnCode()
    assert retCode == 0, "Unable to delete L2 VLAN1001"
    returnStructure = switch.ConfigVtyShell(enter=True)
    LogOutput('info', "### Deleting L3 configuration on interface 2 ###")
    command = "interface 2"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to enter interface context for interface \
            %d" % intf2
    command = "no routing"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to execute 'no routing' for interface \
            %d" % intf2
    command = "routing"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Unable to execute 'routing' for interface %d" % intf2
    LogOutput('info', "### Assigning ip address to interface 2 ###")
    returnStructure = InterfaceIpConfig(
        deviceObj=switch,
        interface=intf2,
        addr="16.1.1.1",
        mask=8,
        config=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot configure ip address on interface %d" % intf2
    LogOutput(
        'info',
        "### Verifying internal VLAN assigned to interface 2 in the DB ###")
    command = "ovs-vsctl get port 2 hw_config:internal_vlan_id"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert '"1001"' in bufferout, "Unable to verify internal VLAN for \
            interface %d in the DB" % intf2


    # Test Case 6:
    # Test case checks if the interfaces are UP in the kernel after
    # "no shutdown" and vice-versa. Also, it verifies that the kernel
    # retains ipv4/ipv6 addresses after "no shutdown"
def portd_functionality_tc6(**kwargs):
    switch = kwargs.get('switch', None)

    # CLI command equivalent of the APIs/commands used below to configure
    # switch
    '''
    switch(config)#interface 3
    switch(config-if)#ipv6 address 1000::1/120
    switch(config-if)#no shutdown
    switch(config-if)#shutdown
    switch(config-if)#no shutdown
    switch(config-if)#exit
    '''
    LogOutput(
        'info',
        "\n\n######## Verifying kernel interfaces if they are 'UP' for"
        " 'no shutdown' case and vice-versa ########")
    LogOutput('info', "### Assigning ipv6 address to interface 3 ###")
    returnStructure = InterfaceIpConfig(
        deviceObj=switch,
        interface=intf3,
        addr="1000::1",
        mask=120,
        ipv6flag=True,
        config=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot configure ipv6 address on interface \
            %d" % intf3
    LogOutput('info', "### Bringing interface 3 up ###")
    returnStructure = InterfaceEnable(
        deviceObj=switch,
        enable=True,
        interface=intf3)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot bring up interface %d" % intf3
    LogOutput('info', "### Verifying interface 3 'up' in the kernel ###")
    command = "ip netns exec swns ifconfig 3"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    out = bufferout.split()
    indexval = out.index("BROADCAST")
    assert 'UP' in out[indexval - 1], "Cannot verify kernel ip \
            address on interface %d to be up" % intf3
    LogOutput(
        'info',
        "### Verifying interface 3 ipv4 and ipv6 addresses in the kernel"
        " after 'no shut'###"
    )
    command = "ip netns exec swns ip addr show 3"
    execute_command_and_verify_response(
        switch=switch,
        command=command,
        max_try=20,
        str1="inet",
        str2="inet6")
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    out = bufferout.split()
    indexval_ipv4 = out.index("inet")
    assert '12.1.1.1/8' in out[indexval_ipv4 + 1], "Cannot verify kernel \
            ip address on interface %d after no-shutdown" % intf3
    indexval_ipv6 = out.index("inet6")
    assert '1000::1/120' in out[indexval_ipv6 + 1], "Cannot verify kernel \
            ipv6 address on interface %d after no-shutdown" % intf3
    LogOutput('info', "### Bringing interface 3 down ###")
    returnStructure = InterfaceEnable(
        deviceObj=switch,
        enable=False,
        interface=intf3)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot bring down interface %d" % intf3
    LogOutput('info', "### Verifying interface 3 'down' in the kernel ###")
    command = "ip netns exec swns ifconfig 3"
    execute_command_and_verify_response(
        switch=switch,
        command=command,
        max_try=10,
        str1="BROADCAST")
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    out = bufferout.split()
    indexval = out.index("BROADCAST")
    assert not 'UP' in out[indexval - 1], "Cannot verify kernel ip \
                address on interface %d to be down" % intf3
    LogOutput(
        'info',
        "### Verifying interface 3 ipv4 address in the kernel after 'shut' ###"
    )
    command = "ip netns exec swns ip addr show 3"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    out = bufferout.split()
    indexval = out.index("inet")
    assert '12.1.1.1/8' in out[indexval + 1], "Cannot verify kernel ip \
                address on interface %d after no-shutdown" % intf3
    LogOutput('info', "### Bringing interface 3 up again ###")
    returnStructure = InterfaceEnable(
        deviceObj=switch,
        enable=True,
        interface=intf3)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Cannot bring up interface %d" % intf3
    LogOutput(
        'info',
        "### Re-verifying interface 3 ipv4 and ipv6 addresses in the kernel" +
        " after 'no shut'###")
    command = "ip netns exec swns ip addr show 3"
    execute_command_and_verify_response(
        switch=switch,
        command=command,
        max_try=10,
        str1="inet",
        str2="inet6")
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    out = bufferout.split()
    indexval_ipv4 = out.index("inet")
    assert '12.1.1.1/8' in out[indexval_ipv4 + 1], "Cannot re-verify kernel \
            ip address on interface %d after no-shutdown" % intf3
    indexval_ipv6 = out.index("inet6")
    assert '1000::1/120' in out[indexval_ipv6 + 1], "Cannot re-verify kernel \
            ipv6 address on interface %d after no-shutdown" % intf3


    # Test Case 7:
    # Test case checks if the interfaces MTU is set kernel after
    # configuring through CLI.
    # Also checks MTU remains unchanged when invalid MTU is configured.
def portd_functionality_tc7(**kwargs):
    switch = kwargs.get('switch', None)

    # CLI command equivalent of the APIs/commands used below to configure
    # switch assuming max_transmission_unit for VSI is 1500.
    '''
    switch(config)#interface 3
    switch(config-if)#no shutdown
    switch(config-if)#no routing
    switch(config-if)#mtu 1400
    switch(config-if)#exit
    switch(config)#interface 3
    switch(config-if)#no shutdown
    switch(config-if)#no routing
    switch(config-if)#mtu 1600
    switch(config-if)#exit
    '''

    LogOutput(
        'info',
        "\n\n######## Assigning MTU values to kernel interfaces ########")

    command = "ovs-vsctl get subsystem base other_info:max_transmission_unit"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    mtu_max = int(bufferout.split('\"')[1])
    mtu_valid = mtu_max - 100
    mtu_invalid = mtu_max + 100

    returnStructure = switch.VtyshShell(enter=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to enter vtysh shell"
    returnStructure = switch.ConfigVtyShell(enter=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to enter config mode"
    command = "interface 3"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to enter interface 3"
    command = "no shut"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to execute no shut"
    command = "no routing"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to execute no routing"
    command = "mtu " + str(mtu_valid)
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to execute 'mtu " + str(mtu_valid) + \
        "' for interface 3"
    command = "exit"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to exit interface 3"
    returnStructure = switch.ConfigVtyShell(enter=False)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to exit config mode"
    returnStructure = switch.VtyshShell(enter=False)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to exit vtysh shell"

    LogOutput('info',
              "### Verifying interface 3 'MTU' value in the kernel ###")
    command = "ip netns exec swns ifconfig 3"
    returnStructure = switch.DeviceInteract(command=command)
    out = returnStructure.get('buffer')
    mtu = int(re.search('\d+', re.search('MTU:\d+', out).group()).group())
    assert (mtu == mtu_valid), "Cannot verify kernel mtu \
                value on interface %d" % intf3

    returnStructure = switch.VtyshShell(enter=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to enter vtysh shell"
    returnStructure = switch.ConfigVtyShell(enter=True)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to enter config mode"
    command = "interface 3"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to enter interface 3"
    command = "no shut"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to execute no shut"
    command = "no routing"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to execute no routing"
    command = "mtu " + str(mtu_invalid)
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to execute 'mtu " + str(mtu_invalid) + \
        "' for interface 3"
    command = "exit"
    returnStructure = switch.DeviceInteract(command=command)
    retCode = returnStructure['returnCode']
    assert retCode == 0, "Unable to exit interface 3"
    returnStructure = switch.ConfigVtyShell(enter=False)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to exit config mode"
    returnStructure = switch.VtyshShell(enter=False)
    retCode = returnStructure.returnCode()
    assert retCode == 0, "Unable to exit vtysh shell"

    LogOutput('info',
              "### Verifying interface 3 with invalid 'MTU'"
              " value in the kernel ###")
    command = "ip netns exec swns ifconfig 3"
    returnStructure = switch.DeviceInteract(command=command)
    out = returnStructure.get('buffer')
    mtu = int(re.search('\d+', re.search('MTU:\d+', out).group()).group())
    assert (mtu == mtu_valid), "Cannot verify kernel mtu \
                value on interface %d" % intf3
    LogOutput('info',
              "### Verifying interface 3 'MTU' value in the "
              "kernel - SUCCESS ###")


@pytest.mark.timeout(500)
@pytest.mark.skipif(True, reason="Disabling old tests")
class Test_portd_functionality:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_portd_functionality.testObj = testEnviron(topoDict=topoDict)
        #    Get topology object
        Test_portd_functionality.topoObj = \
            Test_portd_functionality.testObj.topoObjGet()

    def teardown_class(cls):
        Test_portd_functionality.topoObj.terminate_nodes()

    def test_portd_functionality_tc1(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        portd_functionality_tc1(switch=dut01Obj)

    def test_portd_functionality_tc2(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        portd_functionality_tc2(switch=dut01Obj)

    def test_portd_functionality_tc3(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        portd_functionality_tc3(switch=dut01Obj)

    def test_portd_functionality_tc4(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        portd_functionality_tc4(switch=dut01Obj)

    def test_portd_functionality_tc5(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        portd_functionality_tc5(switch=dut01Obj)

    def test_portd_functionality_tc6(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        portd_functionality_tc6(switch=dut01Obj)

    def test_portd_functionality_tc7(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        portd_functionality_tc7(switch=dut01Obj)
