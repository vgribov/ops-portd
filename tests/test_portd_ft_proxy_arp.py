#!/usr/bin/env python

# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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
import pexpect
import re
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch import *

# Topology definition
# Topology definition
topoDict = {"topoExecution": 15000,
            "topoTarget": "dut01 dut02 dut03",
            "topoDevices": "dut01 dut02 dut03",
            "topoLinks": "lnk01:dut01:dut02,\
                          lnk02:dut01:dut03,\
                          lnk03:dut01:dut02",
            "topoFilters": "dut01:system-category:switch,\
                            dut02:system-category:switch,\
                            dut03:system-category:switch"}


# Support function to reboot the switch
def switch_reboot(deviceObj):
    LogOutput('info', "Reboot switch " + deviceObj.device)
    deviceObj.Reboot()
    rebootRetStruct = returnStruct(returnCode=0)
    return rebootRetStruct


def ping_test(**kwargs):
    switch2 = kwargs.get('switch2', None)

    # Ping IPv4-address from switch2 to switch3
    devIntRetStruct = switch2.DeviceInteract(command="ping 20.0.0.2 \
                                                      repetitions 5")
    retBuffer = devIntRetStruct.get('buffer')
    if 'errors' not in retBuffer:
        LogOutput('info', "Test ping IPv4-address from S2 to S3 passed")
    else:
        LogOutput('info', "Test ping IPv4-address from S2 to S3 failed")


def isMacPresent(string):
    string = str(string)
    p = re.compile(ur'(?:[0-9a-fA-F]:?){12}')
    Mac = re.search(p, string)
    if Mac is None:
        return False
    return True


def getMacFromString(string):
    string = str(string)
    Mac = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})',
                    string, re.I).group()
    return Mac


def show_arp_table(dut):
    devIntReturn = dut.DeviceInteract(command="show arp")
    arp_table = devIntReturn.get('buffer')
    return arp_table


def enterVtysh(dut01):
    retStruct = dut01.DeviceInteract(command="vtysh")
    retCode = retStruct.get('returnCode')
    if retCode == 0:
        return True
    else:
        return False


def exitVtysh(dut01):
    out = dut01.DeviceInteract(command="exit")
    retCode = out.get('returnCode')
    assert retCode == 0, "Failed to exit vtysh"
    return True


def enterInterfaceContext(dut01, interface):
    if(enterVtysh(dut01)) is False:
        print "In Vtysh already"
    retStruct = dut01.ConfigVtyShell(enter=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to enter config terminal"

    cmd = "interface " + str(interface)
    devIntReturn = dut01.DeviceInteract(command=cmd)
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Failed to enter Interface context"

    return True


def exitInterfaceContext(dut01):
    cmd = "exit"
    devIntReturn = dut01.DeviceInteract(command=cmd)
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Failed to exit Interface context"

    retStruct = dut01.ConfigVtyShell(enter=False)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to exit config terminal"

    retStruct = dut01.VtyshShell(enter=False)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to exit vtysh prompt"

    return True


def getSwitchMac(dut01):
    switchMac = ""
    devIntReturn = dut01.DeviceInteract(command="show interface 1")
    systemDetails = devIntReturn.get('buffer')
    switchDetail = systemDetails.split('\r\n')

    for detail in switchDetail:
        if "MAC Address" in detail:
            switchMac = getMacFromString(detail)

    return switchMac


def pingAndVerifyArpTable(dut01, dut02, dut03):
    ping_test(switch1=dut01, switch2=dut02, switch3=dut03)
    switchMac = getSwitchMac(dut01)
    dut02ArpTable = show_arp_table(dut02)
    arpDetail = dut02ArpTable.split('\r\n')
    macInArpTable = ""

    for detail in arpDetail:
        if ("20.0.0.2" in detail) and isMacPresent(detail):
            macInArpTable = getMacFromString(detail)

    if switchMac == macInArpTable:
        return True
    else:
        return False


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


def initial_configure(dut01, dut02, dut03):
    # Enable interface and configure Ip
    LogOutput('info', "Enabling interface1 on %s" % dut01.device)
    interface_value = dut01.linkPortMapping["lnk01"]
    retStruct = InterfaceEnable(deviceObj=dut01,
                                enable=True,
                                interface=interface_value)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to enable interface"

    # Assigning an IPv4 address on interface
    LogOutput('info', "Configuring IPv4 address on link 1 SW1")
    retStruct = InterfaceIpConfig(deviceObj=dut01,
                                  interface=interface_value,
                                  addr="20.0.1.1", mask="24",
                                  config=True)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Failed to configure an IPv4 address on interface "

    # Entering interface for link 1 SW1, giving an IPv6 address
    LogOutput('info', "Configuring IPv6 address on link 1 SW1")
    retStruct = InterfaceIpConfig(deviceObj=dut01,
                                  interface=dut01.linkPortMapping['lnk01'],
                                  addr="1030::2", mask=120,
                                  ipv6flag=True, config=True)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Failed to configure an IPv6 address"

    LogOutput('info', "Enabling interface2 on %s" % dut01.device)
    interface_value = dut01.linkPortMapping["lnk02"]
    retStruct = InterfaceEnable(deviceObj=dut01,
                                enable=True,
                                interface=interface_value)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to enable interface"

    # Assigning an IPv4 address on interface
    LogOutput('info', "Configuring IPv4 address on link 2 SW1")
    retStruct = InterfaceIpConfig(deviceObj=dut01,
                                  interface=interface_value,
                                  addr="20.0.0.1", mask="24",
                                  config=True)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Failed to configure an IPv4 address on interface "

    # Enabling interface2 SW2
    LogOutput('info', "Enabling interface on SW2")
    retStruct = InterfaceEnable(deviceObj=dut02, enable=True,
                                interface=dut02.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to enable interface on SW2"

    # Entering interface for link 2 SW2, giving an IPv6 address
    LogOutput('info', "Configuring IPv6 address on link 1 SW2")
    retStruct = InterfaceIpConfig(deviceObj=dut02,
                                  interface=dut02.linkPortMapping['lnk01'],
                                  addr="1030::3", mask=120, ipv6flag=True,
                                  config=True)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Failed to configure an IPv6 address"

    # Enabling interface2 SW2
    LogOutput('info', "Enabling interface on SW3")
    retStruct = InterfaceEnable(deviceObj=dut03, enable=True,
                                interface=dut03.linkPortMapping['lnk02'])
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to enable interface on SW3"

    # Entering interface for link 2 SW3, giving an IPv4 address
    LogOutput('info', "Configuring IPv4 address on link 2 SW2")
    retStruct = InterfaceIpConfig(deviceObj=dut02,
                                  interface=dut02.linkPortMapping['lnk01'],
                                  addr="20.0.1.2", mask=16, config=True)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Failed to configure an IPv4 address"

    # Entering interface for link 2 SW3, giving an IPv4 address
    LogOutput('info', "Configuring IPv4 address on link 3 SW3")
    retStruct = InterfaceIpConfig(deviceObj=dut03,
                                  interface=dut03.linkPortMapping['lnk02'],
                                  addr="20.0.0.2", mask=24, config=True)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Failed to configure an IPv4 address"

    retStruct = IpRouteConfig(deviceObj=dut03, route="20.0.1.0", mask=24,
                              nexthop="20.0.0.1")
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to add route"


def proxyARPonL3PortTest(dut01, dut02, dut03):
    if pingAndVerifyArpTable(dut01, dut02, dut03):
        assert "Failed to verify that the Proxy ARP funtionality is "\
               "disabled by default"

    if (enterSWNameSpace(dut01) is False):
        return False

    # Routing should be enabled by default
    out = dut01.DeviceInteract(command="sysctl net.ipv4.ip_forward")
    ip_forward_state = out.get('buffer')
    assert 'net.ipv4.ip_forward = 1' in ip_forward_state, "Failed to verify"\
        "ip forwarding is enabled by default"

    # Proxy ARP should be disabled by default
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp = 0' in proxy_arp_state, "Failed to "\
        "verify proxy ARP is disabled by default in kernel via sysctl"

    # Enable Proxy ARP on L3 port
    if (enterInterfaceContext(dut01, 1) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="ip proxy-arp")
    devIntReturn = dut01.DeviceInteract(command="exit")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Enabling Proxy ARP failed"

    if (exitInterfaceContext(dut01) is False):
        return False

    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp = 1' in proxy_arp_state, "Failed to "\
        "verify Proxy ARP is enabled on L3 port in kernel via sysctl"
    if(enterVtysh(dut01) is False):
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 1")
    assert 'Proxy ARP is enabled' in cmdOut, "Failed to validate the" \
        " presence of string 'Proxy ARP is enabled'in show interface output"

    if pingAndVerifyArpTable(dut01, dut02, dut03):
        LogOutput('info', "Proxy ARP functionality successfully verified "
                          " before reboot on a L3 port.")
    else:
        assert "Proxy ARP verification failed."

    # Save the configuration on SW1.
    runCfg = "copy running-config startup-config"
    devIntReturn = dut01.DeviceInteract(command=runCfg)
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Failed to save the running configuration"

    # Perform reboot of SW1.
    devRebootRetStruct = switch_reboot(dut01)
    if devRebootRetStruct.returnCode() != 0:
        LogOutput('error', "Switch1 reboot - FAILED")
        assert(devRebootRetStruct.returnCode() == 0)
    else:
        LogOutput('info', "Switch1 reboot - SUCCESS")

    cmdOut = dut01.cmdVtysh(command="show interface 1")
    assert 'Proxy ARP is enabled' in cmdOut, "Failed to validate the" \
        " presence of string 'Proxy ARP is enabled' in show interface output"

    if pingAndVerifyArpTable(dut01, dut02, dut03):
        LogOutput('info', "Proxy ARP functionality successfully verified after"
                          " reboot on a L3 port.")
    else:
        assert "Proxy ARP verification failed."

    # disabling interface2 SW2
    LogOutput('info', "Disabling interface on SW2")
    retStruct = InterfaceEnable(deviceObj=dut02, enable=False,
                                interface=dut02.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to disable interface on SW2"

    # Enabling interface2 SW2
    LogOutput('info', "Enabling interface on SW2")
    retStruct = InterfaceEnable(deviceObj=dut02, enable=True,
                                interface=dut02.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to enable interface on SW2"

    if (exitVtysh(dut01) is False):
        return False

    # Disable Proxy ARP on L3 port
    if (enterInterfaceContext(dut01, 1) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="no ip proxy-arp")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Disabling Proxy ARP failed"

    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False

    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp = 0' in proxy_arp_state, "Failed to "\
        "verify Proxy ARP is disabled on L3 port in kernel via sysctl"

    if(enterVtysh(dut01)) is False:
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 1")
    assert 'Proxy ARP is enabled' not in cmdOut, "Failed to validate the "\
        "absence of String 'Proxy ARP is enabled' in show interface output "\

    if pingAndVerifyArpTable(dut01, dut02, dut03):
        assert "Verification of Proxy ARP functionality on disable failed"

    if(exitVtysh(dut01)) is False:
        return False

    return True


def proxyARPOnIpChangeAndSecondaryIpConfiguredInterfaceTest(dut01,
                                                            dut02, dut03):
    if (enterSWNameSpace(dut01) is False):
        return False

    if (enterVtysh(dut01) is False):
        return False

    if pingAndVerifyArpTable(dut01, dut02, dut03):
        assert "Verification of Proxy ARP functionality failed"

    if(exitVtysh(dut01)) is False:
        return False

    # Enable Proxy ARP on L3 port
    if (enterInterfaceContext(dut01, 1) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="ip proxy-arp")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Enabling Proxy ARP failed"

    if (exitInterfaceContext(dut01) is False):
        return False

    # Assigning secondary IPv4 address on interface
    LogOutput('info', "Configuring secondary IPv4 address on link 1 SW1")
    retStruct = InterfaceIpConfig(deviceObj=dut01,
                                  interface=dut01.linkPortMapping['lnk01'],
                                  addr="20.0.1.4", mask="16",
                                  secondary=True,
                                  config=True)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Failed to configure a secondary IPv4 address on interface "

    if(enterBashShell(dut01) is False):
        return False

    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp = 1' in proxy_arp_state, "Failed to "\
        "verify Proxy ARP is enabled on L3 port in kernel via sysctl"

    if(enterVtysh(dut01) is False):
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 1")
    assert 'Proxy ARP is enabled' in cmdOut, "Failed to validate the " \
        "presence of string 'Proxy ARP is enabled' in show interface output"

    if pingAndVerifyArpTable(dut01, dut02, dut03):
        LogOutput('info', "Proxy ARP functionality successfully verified.")
    else:
        assert 0, "Proxy ARP verification failed"

    LogOutput('info', "Modifying IPv4 address on link 1 SW1")
    retStruct = InterfaceIpConfig(deviceObj=dut01,
                                  interface=dut01.linkPortMapping['lnk01'],
                                  addr="20.0.1.3", mask="24",
                                  config=True)
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Failed to modify an IPv4 address on interface "

    if pingAndVerifyArpTable(dut01, dut02, dut03):
        LogOutput('info', "Proxy ARP functionality successfully verified.")
    else:
        LogOutput('info', "Proxy ARP verification failed on IP"
                  "address modification .")

    if(exitVtysh(dut01) is False):
        return False

    return True


def proxyARPonL2PortTest(dut01, dut02, dut03):
    # No routing
    if (enterSWNameSpace(dut01) is False):
        return False

    if (enterInterfaceContext(dut01, 1) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="ip proxy-arp")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Enabling Proxy ARP failed"
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False

    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp = 1' in proxy_arp_state, "Failed to "\
        "verify Proxy ARP is enabled on L3 port in kernel via sysctl"

    if(enterVtysh(dut01) is False):
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 1")
    assert 'Proxy ARP is enabled' in cmdOut, "Failed to validate the" \
        " presence of string 'Proxy ARP is enabled' in show interface output"
    if(exitVtysh(dut01) is False):
        return False

    if (enterInterfaceContext(dut01, 1) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="no routing")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "No routing failed"
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False

    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.1.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.1.proxy_arp = 0' in proxy_arp_state, "Failed to "\
        "verify Proxy ARP cannot be enabled on L2 port in kernel via sysctl"

    if(enterVtysh(dut01) is False):
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 1")
    assert 'Proxy ARP is enabled' not in cmdOut, "Failed to validate the "\
        "absence of String 'Proxy ARP is enabled' in show interface output "\

    if(exitVtysh(dut01) is False):
        return False

    return True


def proxyARPonSplitParentInterfaceTest(dut01, dut02, dut03):
    # disabling interface1 SW2
    if (enterSWNameSpace(dut01) is False):
        return False

    if(enterVtysh(dut01) is False):
        return False

    LogOutput('info', "Disabling interface on SW2")
    retStruct = InterfaceEnable(deviceObj=dut02, enable=False,
                                interface=dut02.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to disable interface on SW2"

    # disabling interface1 SW1
    LogOutput('info', "Disabling interface on SW1")
    retStruct = InterfaceEnable(deviceObj=dut01, enable=False,
                                interface=dut01.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to disable interface on SW1"

    # Enabling interface 54 on SW1
    LogOutput('info', "Enabling lnk03 interface on SW1")
    retStruct = InterfaceEnable(deviceObj=dut01, enable=True,
                                interface=dut01.linkPortMapping['lnk03'])
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to enable interface on SW1"

    # Enabling interface1 SW1
    LogOutput('info', "Enabling interface 2 on SW2")
    retStruct = InterfaceEnable(deviceObj=dut02, enable=True,
                                interface=dut02.linkPortMapping['lnk03'])
    retCode = retStruct.returnCode()
    if retCode != 0:
        assert "Unable to enable interface on SW2"

    if(exitVtysh(dut01) is False):
        return False

    # enable Proxy ARP on a non-split parent interface
    if (enterInterfaceContext(dut01, 54) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="ip proxy-arp")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Enabling Proxy ARP failed"
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.54.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.54.proxy_arp = 1' in proxy_arp_state, "Failed to "\
        "verify Proxy ARP is Enabled on a non split parent interface in "\
        "kernel via sysctl"

    if(enterVtysh(dut01)) is False:
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 54")
    assert 'Proxy ARP is enabled' in cmdOut, "Failed to validate the " \
        "presence of string 'Proxy ARP is enabled' in show interface output"

    if(exitVtysh(dut01) is False):
        return False

    # Proxy ARP should be disabled on a split interface.
    if (enterInterfaceContext(dut01, 54) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="split \n y")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Split failed"
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.54.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.54.proxy_arp = 0' in proxy_arp_state, "Failed to "\
        "verify Proxy ARP is disabled on split interface in kernel via sysctl"

    if(enterVtysh(dut01)) is False:
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 54")
    assert 'Proxy ARP is enabled' not in cmdOut, "Failed to validate the "\
        "absence of String 'Proxy ARP is enabled' in show interface output "\

    if(exitVtysh(dut01) is False):
        return False

    return True


def proxyARPonSplitChildInterfaceTest(dut01, dut02, dut03):
    if (enterSWNameSpace(dut01) is False):
        return False

    # Proxy ARP on a non-split child interface
    if (enterInterfaceContext(dut01, 53-1) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="ip proxy-arp")
    retCode = devIntReturn.get('returnCode')
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.53-1.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.53-1.proxy_arp = 0' in proxy_arp_state, "Failed to "\
        "verify Proxy ARP is not enabled for a non split child interface in "\
        "kernel via sysctl"

    if(enterVtysh(dut01)) is False:
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 53-1")
    assert 'Proxy ARP is enabled' not in cmdOut, "Failed to validate the "\
        "absence of String 'Proxy ARP is enabled' in show interface output "\

    if(exitVtysh(dut01) is False):
        return False

    # Split interface.
    if (enterInterfaceContext(dut01, 53) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="split \n y")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Split failed"
    if (exitInterfaceContext(dut01) is False):
        return False

    if(exitVtysh(dut01) is False):
        return False

    # Proxy ARP on a split child interface
    if (enterInterfaceContext(dut01, "53-1") is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="ip proxy-arp")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Enabling proxy ARP failed"
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.53-1.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.53-1.proxy_arp = 1' in proxy_arp_state, "Failed to "\
        "verify Proxy ARP is enabled on split child interface in kernel "\
        "via sysctl"

    if(enterVtysh(dut01)) is False:
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 53-1")
    assert 'Proxy ARP is enabled' in cmdOut, "Failed to validate the "\
        "presence of String 'Proxy ARP is enabled' in show interface output "\

    if(exitVtysh(dut01) is False):
        return False

    # Disable Split interface.
    if (enterInterfaceContext(dut01, 53) is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="no split \n yes")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "no split failed"
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False

    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.53-1.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.53-1.proxy_arp = 0' in proxy_arp_state, "Failed to "\
        "verify in kernel via sysctl that Proxy ARP is disabled on child "\
        "interface when parent interface is reset to no split."

    if(enterVtysh(dut01)) is False:
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 53-1")
    assert 'Proxy ARP is enabled' not in cmdOut, "Failed to validate the "\
        "absence of String 'Proxy ARP is enabled' in show interface output "\

    if(exitVtysh(dut01) is False):
        return False

    return True


def proxyARPonVLANInterfaceTest(dut01, dut02, dut03):
    if (enterSWNameSpace(dut01) is False):
        return False

    # enable Proxy ARP on L3 VLAN interface
    if (enterInterfaceContext(dut01, "vlan 3") is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="ip proxy-arp")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Enabling Proxy ARP failed"
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.vlan3.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.vlan3.proxy_arp = 1' in proxy_arp_state, "Failed to"\
        " verify Proxy ARP is enabled on vlan interface in kernel via sysctl"

    # Disable Proxy ARP on L3 vlan interface
    if (enterInterfaceContext(dut01, "vlan 3") is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="no ip proxy-arp")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Disabling Proxy ARP failed"
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterBashShell(dut01) is False):
        return False
    out = dut01.DeviceInteract(command="sysctl net.ipv4.conf.vlan3.proxy_arp")
    proxy_arp_state = out.get('buffer')
    assert 'net.ipv4.conf.vlan3.proxy_arp = 0' in proxy_arp_state, "Failed to"\
        " verify Proxy ARP is disabled on vlan interface in kernel via sysctl"

    return True


def proxyARPonSubInterfaceTest(dut01, dut02, dut03):
    if (enterSWNameSpace(dut01) is False):
        return False

    # Try enable Proxy ARP on sub-interface
    if (enterInterfaceContext(dut01, "1.1") is False):
        return False
    devIntReturn = dut01.DeviceInteract(command="ip proxy-arp")
    if (exitInterfaceContext(dut01) is False):
        return False

    if(enterVtysh(dut01)) is False:
        return False

    cmdOut = dut01.cmdVtysh(command="show interface 1.1")
    assert 'Proxy ARP is enabled' not in cmdOut, "Failed to validate the "\
        "absence of String 'Proxy ARP is enabled' in show interface output "\

    return True


class Test_proxyarp_feature:
    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_proxyarp_feature.testObj =\
            testEnviron(topoDict=topoDict, defSwitchContext="vtyShell")
        # Get topology object
        Test_proxyarp_feature.topoObj = \
            Test_proxyarp_feature.testObj.topoObjGet()

    def teardown_class(cls):
        Test_proxyarp_feature.topoObj.terminate_nodes()

    def test_proxyARPOnL3Port(self):
        LogOutput('info', "\n### Test Proxy ARP on L3 port ###")
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")
        dut03Obj = self.topoObj.deviceObjGet(device="dut03")

        initial_configure(dut01Obj, dut02Obj, dut03Obj)
        retValue = proxyARPonL3PortTest(dut01Obj, dut02Obj, dut03Obj)
        if(retValue):
            LogOutput('info', "Proxy ARP on L3 port - passed")
        else:
            LogOutput('error', "Proxy ARP on L3 port - failed")

    def test_proxyARPOnIpChangeAndSecondaryIpConfiguredInterface(self):
        LogOutput('info', "\n### Test Proxy ARP on Ip Change And Secondary"
                  "IpConfiguredInterface ###")
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")
        dut03Obj = self.topoObj.deviceObjGet(device="dut03")

        retValue = proxyARPOnIpChangeAndSecondaryIpConfiguredInterfaceTest(
                                 dut01Obj, dut02Obj, dut03Obj)
        if(retValue):
            LogOutput('info', "Proxy ARP on Secondary IpConfigured "
                              "Interface - passed")
        else:
            LogOutput('info', "Proxy ARP on Secondary IpConfigured "
                              "Interface - failed")

    def test_proxyARPOnL2Port(self):
        LogOutput('info', "\n### Test Proxy ARP on L2 port ###")
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")
        dut03Obj = self.topoObj.deviceObjGet(device="dut03")

        retValue = proxyARPonL2PortTest(dut01Obj, dut02Obj, dut03Obj)
        if(retValue):
            LogOutput('info', "Proxy ARP on L2 port - passed")
        else:
            LogOutput('error', "Proxy ARP on L2 port - failed")

    def test_proxyARPOnSplitParentPort(self):
        LogOutput('info', "\n### Test Proxy ARP on Split Parent port ###")
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")
        dut03Obj = self.topoObj.deviceObjGet(device="dut03")

        retValue = proxyARPonSplitParentInterfaceTest(dut01Obj, dut02Obj,
                                                      dut03Obj)
        if(retValue):
            LogOutput('info', "Proxy ARP on split parent interface - passed")
        else:
            LogOutput('error', "Proxy ARP on split parent interface - failed")

    def test_proxyARPOnSplitChildPort(self):
        LogOutput('info', "\n### Test Proxy ARP on Split child port ###")
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")
        dut03Obj = self.topoObj.deviceObjGet(device="dut03")

        retValue = proxyARPonSplitChildInterfaceTest(dut01Obj, dut02Obj,
                                                     dut03Obj)
        if(retValue):
            LogOutput('info', "Proxy ARP on split child interface - passed")
        else:
            LogOutput('error', "Proxy ARP on split child interface - failed")

    def test_proxyARPOnVLANInterface(self):
        LogOutput('info', "\n### Test Proxy ARP on VLAN Interface ###")
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")
        dut03Obj = self.topoObj.deviceObjGet(device="dut03")

        retValue = proxyARPonVLANInterfaceTest(dut01Obj, dut02Obj, dut03Obj)
        if(retValue):
            LogOutput('info', "Proxy ARP on VLAN interface - passed")
        else:
            LogOutput('error', "Proxy ARP on VLAN interface - failed")

    def test_proxyARPOnSubInterface(self):
        LogOutput('info', "\n### Test Proxy ARP on sub-interface ###")
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")
        dut03Obj = self.topoObj.deviceObjGet(device="dut03")

        retValue = proxyARPonSubInterfaceTest(dut01Obj, dut02Obj, dut03Obj)
        if(retValue):
            LogOutput('info', "Proxy ARP on Sub-interface - passed")
        else:
            LogOutput('error', "Proxy ARP on Sub-interface - failed")
