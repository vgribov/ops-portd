# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
OpenSwitch Test for event loggings for loopback interface
and sub interface. The test case also convers the diag-dump
information for loopback and sub-interface. The "show tech basic"
is tested for loopback interface information.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division


TOPOLOGY = """
# +-------+
# |  sw1  |
# +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1

# Links
"""


def loopback_interface_events_test(dut, step):
    """
    Testcase for Loopback interface events logging.
    """
    loopback_created = False
    loopback_deleted = False
    loopback_ip_added = False
    loopback_ip_deleted = False
    loopback_ipv6_added = False
    loopback_ipv6_deleted = False
    step("Configure loopback interface and assign an IPv4 address")
    with dut.libs.vtysh.ConfigInterfaceLoopback('10') as ctx:
        ctx.ip_address("10.1.1.1/24")

    lo_exp_out = "Loopback Interface lo10, created"
    ip_exp_out = "Loopback Interface lo10, configured with ip address " \
                 "10.1.1.1/24"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if lo_exp_out in line:
            loopback_created = True
        if ip_exp_out in line:
            loopback_ip_added = True
    assert (loopback_created is True),  "Loopback interface not created."
    assert (loopback_ip_added is True), "Loopback interface: Unable to " \
                                        "add IPv4 address"

    step("Unconfigure IPv4 address from the loopback interface")
    with dut.libs.vtysh.ConfigInterfaceLoopback('10') as ctx:
        ctx.no_ip_address("10.1.1.1/24")

    ipdl_exp_out = "Loopback Interface lo10, ipv4 address deleted"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if ipdl_exp_out in line:
            loopback_ip_deleted = True
    assert (loopback_ip_deleted is True), "Loopback interface: IPv4 " \
                                          "address unable to remove"

    step("Assign IPv6 address to the loopback interface")
    with dut.libs.vtysh.ConfigInterfaceLoopback('10') as ctx:
        ctx.ipv6_address("abcf::12/64")

    ipv6_exp_out = "Loopback Interface lo10, configured with ip " \
                   "address abcf::12/64"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if ipv6_exp_out in line:
            loopback_ipv6_added = True
    assert (loopback_ipv6_added is True), "Loopback interface: Unable to " \
                                          "add IPv6 address"

    step("Unconfigure IPv6 address from the loopback interface")
    with dut.libs.vtysh.ConfigInterfaceLoopback('10') as ctx:
        ctx.no_ipv6_address("abcf::12/64")
    ipv6dl_exp_out = "Loopback Interface lo10, ipv6 address deleted"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if ipv6dl_exp_out in line:
            loopback_ipv6_deleted = True
    assert (loopback_ipv6_deleted is True), "Loopback interface: IPv6 " \
                                            "address unable to remove"

    step("Delete the loopback interface")
    with dut.libs.vtysh.Configure() as ctx:
        ctx.no_interface_loopback("10")
    lodl_exp_out = "Loopback Interface lo10, deleted"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if lodl_exp_out in line:
            loopback_deleted = True
    assert (loopback_deleted is True), "Unable to delete loopback interface."


def sub_interface_events_test(dut, step):
    """
    Test case for Sub-interface events logging
    """
    subint_created = False
    subint_deleted = False
    subint_ip_added = False
    subint_ip_deleted = False
    subint_ipv6_added = False
    subint_ipv6_deleted = False
    subint_dot1q_added = False
    subint_dot1q_deleted = False
    step("Configure a sub-interface")
    with dut.libs.vtysh.ConfigInterface('10.10') as ctx:
        ctx.no_shutdown()

    subint_exp_out = "Sub-Interface 10.10, created"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if subint_exp_out in line:
            subint_created = True
    assert (subint_created is True),  "Sub-interface not created."

    ip_exp_out = "Sub-Interface 10.10, configured with ip address " \
                 "20.2.2.2/24"

    step("Configure IPv4 address in the sub-interface")
    with dut.libs.vtysh.ConfigInterface('10.10') as ctx:
        ctx.ip_address("20.2.2.2/24")

    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if ip_exp_out in line:
            subint_ip_added = True
    assert (subint_ip_added is True), "Sub-interface: Unable to " \
                                      "add IPv4 address"

    step("Unconfigure IPv4 address from the sub-interface")
    with dut.libs.vtysh.ConfigInterface('10.10') as ctx:
        ctx.no_ip_address("20.2.2.2/24")

    ipdl_exp_out = "Sub-Interface 10.10, ipv4 address deleted"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if ipdl_exp_out in line:
            subint_ip_deleted = True
    assert (subint_ip_deleted is True), "Sub-interface: Unable to remove " \
                                        "IPv4 address"

    step("Configure IPv6 address from the sub-interface")
    with dut.libs.vtysh.ConfigInterface('10.10') as ctx:
        ctx.ipv6_address("abcd::201/64")

    ipv6_exp_out = "Sub-Interface 10.10, configured with ip " \
                   "address abcd::201/64"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if ipv6_exp_out in line:
            subint_ipv6_added = True
    assert (subint_ipv6_added is True), "Sub-interface: Unable to " \
                                        "add IPv6 address"

    step("Unconfigure IPv6 address from the sub-interface")
    with dut.libs.vtysh.ConfigInterface('10.10') as ctx:
        ctx.no_ipv6_address("abcd::201/64")

    ipv6dl_exp_out = "Sub-Interface 10.10, ipv6 address deleted"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if ipv6dl_exp_out in line:
            subint_ipv6_deleted = True
    assert (subint_ipv6_deleted is True), "Sub-interface: IPv6 " \
                                          "address unable to remove"

    step("Configure dot encapsulation in the sub-interface")
    encap_exp_out = "Sub-Interface 10.10, configured with dot " \
                    "encapsulation 10"
    dut("configure terminal")
    dut("interface 10.10")
    dut("encapsulation dot1Q 10")
    dut("end")
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if encap_exp_out in line:
            subint_dot1q_added = True
    assert (subint_dot1q_added is True), "Sub-interface: Unable to " \
                                         "add dot1Q encapsulation"

    step("Unconfigure the dot encapsulation from the sub-interface")
    noencap_exp_out = "Sub-Interface 10.10, configured with " \
                      "dot encapsulation 0"
    dut("configure terminal")
    dut("interface 10.10")
    dut("no encapsulation dot1Q 10")
    dut("end")
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if noencap_exp_out in line:
            subint_dot1q_deleted = True
    assert (subint_dot1q_deleted is True), "Sub-interface: Unable to "\
                                           "remove dot1Q encapsulation"

    step("Delete the sub-interface")
    dut("configure terminal")
    dut("no interface 10.10")
    dut("end")
    subintdl_exp_out = "Sub-Interface 10.10, deleted"
    out = dut('show events')
    lines = out.splitlines()
    for line in lines:
        if subintdl_exp_out in line:
            subint_deleted = True
    assert (subint_deleted is True), "Unable to delete sub-interface."


def diag_dump_loopback(dut, step):
    """
    Test case to verify the "diag-dump loopback basic" information with
    different number of loopback interfaces
    """
    lo_diag_added = False
    total_lo = []
    step("Configure 4 Loopback interfaces and verify in diag-dump")
    with dut.libs.vtysh.ConfigInterfaceLoopback('10') as ctx:
        ctx.ip_address("1.1.1.1/24")
    with dut.libs.vtysh.ConfigInterfaceLoopback('11') as ctx:
        ctx.ip_address("2.2.2.2/24")
    with dut.libs.vtysh.ConfigInterfaceLoopback('12') as ctx:
        ctx.ip_address("3.3.3.3/24")
    with dut.libs.vtysh.ConfigInterfaceLoopback('13') as ctx:
        ctx.ip_address("4.4.4.4/24")
    out = dut("diag-dump loopback basic")
    lo_diag_exp_out = "Number of Configured loopback interfaces are"
    lines = out.splitlines()
    for line in lines:
        if lo_diag_exp_out in line:
            lo_diag_added = True
            line = line.replace(".", "")
            total_lo = [int(i) for i in line.split() if i.isdigit()]
    assert (lo_diag_added is True and
            total_lo[0] == 4)

    step("Delete two loopback interfaces and verify in diag-dump")
    with dut.libs.vtysh.Configure() as ctx:
        ctx.no_interface_loopback("12")
    with dut.libs.vtysh.Configure() as ctx:
        ctx.no_interface_loopback("13")
    out = dut("diag-dump loopback basic")
    lines = out.splitlines()
    for line in lines:
        if lo_diag_exp_out in line:
            line = line.replace(".", "")
            total_lo = [int(i) for i in line.split() if i.isdigit()]
    assert (total_lo[0] == 2), "Incorrect number of loopback" \
                               "interfaces found"

    step("Delete all the loopback interfaces and verify in diag-dump")
    with dut.libs.vtysh.Configure() as ctx:
        ctx.no_interface_loopback("10")
    with dut.libs.vtysh.Configure() as ctx:
        ctx.no_interface_loopback("11")
    out = dut("diag-dump loopback basic")
    lines = out.splitlines()
    for line in lines:
        if lo_diag_exp_out in line:
            line = line.replace(".", "")
            total_lo = [int(i) for i in line.split() if i.isdigit()]
    assert (total_lo[0] == 0), "Incorrect number of loopback" \
                               "interfaces found"


def diag_dump_subintf(dut, step):
    """
    Test case to verify the "diag-dump sub-interface basic" information with
    different number of sub-interfaces
    """
    subintf_diag_added = False
    total_subintf = []
    step("Configure 4 Loopback interfaces and verify in diag-dump")
    with dut.libs.vtysh.ConfigInterface('10.10') as ctx:
        ctx.no_shutdown()
    with dut.libs.vtysh.ConfigInterface('11.10') as ctx:
        ctx.no_shutdown()
    with dut.libs.vtysh.ConfigInterface('12.10') as ctx:
        ctx.no_shutdown()
    with dut.libs.vtysh.ConfigInterface('13.10') as ctx:
        ctx.no_shutdown()
    out = dut("diag-dump sub-interface basic")
    subintf_diag_exp_out = "Number of Configured sub-interfaces are"
    lines = out.splitlines()
    for line in lines:
        if subintf_diag_exp_out in line:
            subintf_diag_added = True
            line = line.replace(".", "")
            total_subintf = [int(i) for i in line.split() if i.isdigit()]
    assert (subintf_diag_added is True and
            total_subintf[0] == 4)

    step("Delete two sub-interfaces and verify in diag-dump")
    dut("configure terminal")
    dut("no interface 12.10")
    dut("no interface 13.10")
    dut("end")
    out = dut("diag-dump sub-interface basic")
    lines = out.splitlines()
    for line in lines:
        if subintf_diag_exp_out in line:
            line = line.replace(".", "")
            total_subintf = [int(i) for i in line.split() if i.isdigit()]
    assert (total_subintf[0] == 2), "Incorrect number of sub-interface" \
                                    "interfaces found"

    step("Delete all the sub-interfaces and verify in diag-dump")
    dut("configure terminal")
    dut("no interface 10.10")
    dut("no interface 11.10")
    dut("end")
    out = dut("diag-dump sub-interface basic")
    lines = out.splitlines()
    for line in lines:
        if subintf_diag_exp_out in line:
            line = line.replace(".", "")
            total_subintf = [int(i) for i in line.split() if i.isdigit()]
    assert (total_subintf[0] == 0), "Incorrect number of sub-interface" \
                                    "interfaces found"


def show_tech_loopback(dut, step):
    """
    Test case to verify the loopback interface information in
    "show tech basic" command
    """
    step("Configure a loopback interface")
    success = 0
    with dut.libs.vtysh.ConfigInterfaceLoopback('10') as ctx:
        ctx.ip_address("5.5.5.5/24")
    step("Verify loopback interface information in \"show tech\"")
    lo_tech_exp = ["Interface lo10 is up", "IPv4 address 5.5.5.5/24"]
    out = dut("show tech basic")
    lines = out.splitlines()
    for line in lines:
        if lo_tech_exp[0] in line:
            success += 1
        if lo_tech_exp[1] in line:
            success += 1
    assert (success == 2), "loopback interface information not found" \
                           "in show tech basic"

    step("Verify loopback interface removal from \"show tech\""
         "after deletion of loopback interface")
    with dut.libs.vtysh.Configure() as ctx:
        ctx.no_interface_loopback("10")
    out = dut("show tech basic")
    lines = out.splitlines()
    for line in lines:
        if lo_tech_exp[0] in line:
            success -= 1
        if lo_tech_exp[1] in line:
            success -= 1
    assert (success == 2), "loopback interface information were not " \
                           "removed from show tech basic"


def test_portd_events(topology, step):
    """
    Test case to verify the event logs in "show events" command
    and the loopback interface information in "diag-dump loopback basic"
    and "show tech basic"
    """
    sw1 = topology.get('sw1')

    assert sw1 is not None

    step("Test the event logging for loopback interfaces")
    loopback_interface_events_test(sw1, step)
    step("Test the event logging for sub-interfaces")
    sub_interface_events_test(sw1, step)
    step("Test for the diag-dump information for loopback interface")
    diag_dump_loopback(sw1, step)
    step("Test for the diag-dump information for sub-interface")
    diag_dump_subintf(sw1, step)
    step("Test for the \"show tech basic\" information for loopback"
         "interface")
    show_tech_loopback(sw1, step)
