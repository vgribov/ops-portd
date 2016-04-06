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

import time
import pytest
import re
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoTarget": "dut01",
            "topoDevices": "dut01 wrkston01",
            "topoLinks": "lnk01:dut01:wrkston01",
            "topoFilters": "dut01:system-category:switch,\
                            wrkston01:system-category:workstation"}


def portd(**kwargs):
    device1 = kwargs.get('device1', None)
    device2 = kwargs.get('device2', None)

# test cases for sub interface ...
    LogOutput('info', "Teestcases for subinterface")

# creating a Parent interface
    retStruct = InterfaceEnable(deviceObj=device1, enable=True,
                                interface="4")
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enable interface")
        assert(False)
    retStruct = InterfaceIpConfig(deviceObj=device1,
                                  interface="4",
                                  addr="192.168.1.5", mask=24, config=True)

# creating the subinterface and verifying it
    retStruct = InterfaceEnable(deviceObj=device1, enable=True,
                                interface="4.2")
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enable interface")
        assert(False)
    time.sleep(6)
    LogOutput('info', "### Verify the interface is created with \
              same name for L3 port ###")
    cmd = "ip netns exec swns ifconfig 4.2"
    devIntReturn = device1.DeviceInteract(command=cmd)
    retCode = devIntReturn.get('buffer')
    assert "4.2"in retCode, "Failed to retrieve ovs-vsctl command"
    LogOutput('info', "### interface 4.2 created successfully!!!! ###")

# configuerd the ip
    retStruct = InterfaceIpConfig(deviceObj=device1,
                                  interface="4.2",
                                  addr="192.158.1.5", mask=24, config=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "### Failed to configure interface Ip address ###")
        assert(False)
    retStruct = Dot1qEncapsulation(deviceObj=device1, subInterface="4.2",
                                   dot1q=True, vlan=100)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enable dot1Q encapsulation")
        assert(False)
    devIntReturn = device1.DeviceInteract(command=cmd)
    retCode = devIntReturn.get('buffer')
    assert "inet addr:192.158.1.5"in retCode, \
           "Failed to retrieve ovs-vsctl command"
    LogOutput('info', "### IP assigned successfully for 4.2!!!!###")

# verifying ping
    devIntReturn = device1.DeviceInteract(command="vtysh")
    devIntReturn = device1.DeviceInteract(command="ping 192.158.1.5")
    retCode = devIntReturn.get('buffer')
    assert "5 packets transmitted, 5 received" in retCode,\
           "ping is not success!!!"
    LogOutput('info', "ping sucess!!!!")
    devIntReturn = device1.DeviceInteract(command="exit")

# No Dot1Q encapsulation
    retStruct = Dot1qEncapsulation(deviceObj=device1, subInterface="4.2",
                                   dot1q=False, vlan=100)
    devIntReturn = device1.DeviceInteract(command=cmd)
    retCode = devIntReturn.get('buffer')
    assert "inet addr:192.158.1.5" not in retCode, \
    'failed!! to remove Ip address from kernel name space'

# deconfiguring the i/p
    retStruct = InterfaceEnable(deviceObj=device1, enable=True,
                                interface="4.7")
    retStruct = InterfaceIpConfig(deviceObj=device1,
                                  interface="4.7",
                                  addr="192.158.1.3", mask=24, config=True)

    retStruct = InterfaceIpConfig(deviceObj=device1,
                                  interface="4.7",
                                  addr="192.158.1.3", mask=24, config=False)

    devIntReturn = device1.DeviceInteract(command=
    "ip netns exec swns ifconfig 4.7")
    retCode = devIntReturn.get('buffer')
    assert "inet addr:192.158.1.3" not in retCode, "Failed to remove IP adrs!"

# verifying ping
    devIntReturn = device1.DeviceInteract(command="vtysh")
    devIntReturn = device1.DeviceInteract(command="ping 192.158.1.5")
    retCode = devIntReturn.get('buffer')
    assert "5 packets transmitted, 5 received" not in retCode,\
    "ping is still success"
    devIntReturn = device1.DeviceInteract(command="exit")

# parent interface moves to L3 from L2 and vise versa - subinterfaces state
    devIntReturn = device1.DeviceInteract(command="vtysh")
    devIntReturn = device1.DeviceInteract(command="conf t")
    devIntReturn = device1.DeviceInteract(command="int 4")
    devIntReturn = device1.DeviceInteract(command="no routing")
    devIntReturn = device1.DeviceInteract(command="exit")
    devIntReturn = device1.DeviceInteract(command="exit")
    devIntReturn = device1.DeviceInteract(command="exit")
    devIntReturn = device1.DeviceInteract(command=
    "ip netns exec swns ifconfig 4.7")
    retCode = devIntReturn.get('buffer')
    assert "ifconfig: error: interface `4.7' does not exist" in retCode, \
    "Failed!! still link Up in L2 parent Interface"

# subinterface will down when parent will down
    retStruct = InterfaceEnable(deviceObj=device1, enable=True,
                                interface="7")
    retStruct = InterfaceIpConfig(deviceObj=device1,
                                  interface="7",
                                  addr="152.20.1.4", mask=24, config=True)
    retStruct = InterfaceEnable(deviceObj=device1, enable=True,
                                interface="7.2")
    retStruct = InterfaceIpConfig(deviceObj=device1,
                                  interface="7.2",
                                  addr="172.168.1.4", mask=24, config=True)
    retStruct = Dot1qEncapsulation(deviceObj=device1, subInterface="7.2",
                                   dot1q=True, vlan=10)

    result = "ip netns exec swns ifconfig 7.2"
    devIntReturn = device1.DeviceInteract(command=result)
    retCode = devIntReturn.get('buffer')
    assert "UP"in retCode, \
           "Failed to retrieve ovs-vsctl command"
    retStruct = InterfaceEnable(deviceObj=device1, enable=False,
                                interface="7")
    devIntReturn = device1.DeviceInteract(command=result)
    retCode = devIntReturn.get('buffer')
    assert "UP" not in retCode, \
           "Failed to retrieve ovs-vsctl command"

# Deleting sub interface
    devIntReturn = device1.DeviceInteract(command="vtysh")
    devIntReturn = device1.DeviceInteract(command="conf t")
    devIntReturn = device1.DeviceInteract(command="no int 4.2")
    devIntReturn = device1.DeviceInteract(command="exit")
    devIntReturn = device1.DeviceInteract(command="exit")
    devIntReturn = device1.DeviceInteract(command=cmd)
    retCode = devIntReturn.get('buffer')
    assert "ifconfig: error: interface `4.2' does not exist" in retCode, \
    'sub interface 4.2 not  deleted'

# Re-start ability of portd and intfd  either together or one at a time
# test case-1
    retStruct = InterfaceEnable(deviceObj=device1, enable=True,
                                interface="5")
    retStruct = InterfaceEnable(deviceObj=device1, enable=True,
                                interface="5.6")
    devIntReturn = device1.DeviceInteract(command="systemctl stop ops-portd")
    ifcon = "ip netns exec swns ifconfig 5.6"
    devIntReturn = device1.DeviceInteract(command=ifcon)
    retCode = devIntReturn.get('buffer')
    assert "5.6"in retCode, "sub interface 5.6 is in kernelname space!!!!"
    devIntReturn = device1.DeviceInteract(command="vtysh")
    devIntReturn = device1.DeviceInteract(command="conf t")
    devIntReturn = device1.DeviceInteract(command="no int 5.6")
    devIntReturn = device1.DeviceInteract(command="exit")
    devIntReturn = device1.DeviceInteract(command="exit")
    devIntReturn = device1.DeviceInteract(command=ifcon)
    retCode = devIntReturn.get('buffer')
    assert "5.6"in retCode, "sub interface 5.6 is in kernelname space!!!!"

    devIntReturn = device1.DeviceInteract(command="systemctl start ops-portd")
    devIntReturn = device1.DeviceInteract(command=ifcon)
    retCode = devIntReturn.get('buffer')
    assert "ifconfig: error: interface `5.6' does not exist" in retCode, \
    "sub int 5.6 still in kernelname space- Failed!!!!"

# test cases for loop back
    LogOutput('info', "*** Test cases for loopback interface ***")

# enabling the loopback interface
    retStruct = LoopbackInterfaceEnable(deviceObj=device1,
                                        loopback="1", config=True, enable=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enable the loopback interface")
        assert(False)
    cmnd = "ip netns exec swns ifconfig lo:1"
    devIntReturn = device1.DeviceInteract(command=cmnd)
    retCode = devIntReturn.get('buffer')
    assert "lo:1"in retCode, "Failed to retrieve ovs-vsctl command"
    LogOutput('info', "### lo:1 created successfully ###")

# configuring the ip address and verifying
    retStruct = LoopbackInterfaceEnable(deviceObj=device1,
                                        loopback="1", addr="192.168.1.5",
                                        mask=24, config=True, enable=True)

    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to configure interface IP address")
        assert(False)
    devIntReturn = device1.DeviceInteract(command=cmnd)
    retCode = devIntReturn.get('buffer')
    assert "inet addr:192.168.1.5 "in retCode,\
           "Failed to retrieve ovs-vsctl command"
    LogOutput('info', "### IP assigned successfully for lo:1 !!###")

# verifying ping from host
    devIntReturn = device1.DeviceInteract(command="vtysh")
    devIntReturn = device1.DeviceInteract(command="ping 192.168.1.5")
    retCode = devIntReturn.get('buffer')
    assert "5 packets transmitted, 5 received" in retCode,\
           "ping is not success!!!"
    LogOutput('info', "ping sucess!!!!")
    devIntReturn = device1.DeviceInteract(command="exit")

# deconfiguring the ip addressand verifying
    retStruct = LoopbackInterfaceEnable(deviceObj=device1,
                                        loopback="1", addr="192.168.1.5",
                                        mask=24, config=False, enable=True)

    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to configure interface IP address")
        assert(False)
    devIntReturn = device1.DeviceInteract(command=cmnd)
    retCode = devIntReturn.get('buffer')
    assert"inet addr:192.168.1.5" not in retCode, \
    "Failed to unassign IP address!!"

# verifying ping
    devIntReturn = device1.DeviceInteract(command="vtysh")
    devIntReturn = device1.DeviceInteract(command="ping 192.168.1.2")
    retCode = devIntReturn.get('buffer')
    assert "5 packets transmitted, 5 received" not in retCode,\
    "ping is still success"
    devIntReturn = device1.DeviceInteract(command="exit")

# deleting the loopback interface and verifying
    retStruct = LoopbackInterfaceEnable(deviceObj=device1,
                                        loopback="1", enable=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to rmove the loopback interface")
        assert(False)
    devIntReturn = device1.DeviceInteract(command=cmnd)
    retCode = devIntReturn.get('buffer')
    assert "inet addr:192.168.1.5" not in retCode, "Failed to remove lo:1"


@pytest.mark.skipif(True, reason="Disabling old tests")
class Test_portd:
    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_portd.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_portd.topoObj = Test_portd.testObj.topoObjGet()
        if Test_portd.topoObj.topoType == "physical":
            LogOutput('info',
                      "Skipping test physical run due to defect #744")
            pytest.skip("Skipping test physical run due to defect #744")

    def teardown_class(cls):
        Test_portd.topoObj.terminate_nodes()

    def test_portd(self):
        LogOutput('info', "**configuring**")
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        wrkston1Obj = self.topoObj.deviceObjGet(device="wrkston01")
        retValue = portd(device1=dut01Obj, device2=wrkston1Obj)
