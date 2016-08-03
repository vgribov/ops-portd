# -*- coding: utf-8 -*-
# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
# GNU Zebra is free software; you can rediTestribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# GNU Zebra is diTestributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; withoutputputputput even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Zebra; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, BoTeston, MA
# 02111-1307, USA.

from re import search
import pytest
import re
import collections

TOPOLOGY = """
#
# +-------+                  +-------+
# |       |     +-------+    |       |
# |  sw2  <----->  sw1  <---->  sw3  |
# |       |     +-------+    |       |
# +-------+                  +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=openswitch name="Switch 2"] sw2
[type=openswitch name="Switch 3"] sw3

# Interfaces
sw1:if01
sw1:if02
sw1:if03
sw1:if04

# Links
sw1:if01 -- sw2:if01
sw1:if02 -- sw3:if01
"""

def get_vrf_uuid(sw1, vrf_name):
    vrf_string = None
    if (vrf_name == "vrf_default"):
        vrf_string = "swns"
    else:
        output = sw1("ovs-vsctl list vrf "+vrf_name, shell='bash')
        uuid_detail = output.split('\n')

        for detail in uuid_detail:
            if "_uuid" in detail:
                vrf_uuid_split = detail.split(':')
                vrf_uuid = vrf_uuid_split[1]
                vrf_string = vrf_uuid.strip()
                break

    out = sw1("ip netns", shell='bash')
    assert vrf_string in out, "VRF is not found."

    print ("VRF "+vrf_name+" is present with UUID "+vrf_string)
    return vrf_string


def create_vrf_and_get_vrf_UUID(sw1, vrf_name):
    sw1("config terminal")
    sw1("vrf "+vrf_name)
    sw1("end")

    print ("Configured VRF "+vrf_name)
    return get_vrf_uuid(sw1, vrf_name)


# Test Case 1:
# Test case checks if the interfaces are UP in the kernel after
# "no shutdown" and vice-versa with non default vrf. Also, it verifies
# that the kernel retains ipv4/ipv6 addresses after "no shutdown",
# with non default-vrf
def portd_functionality_tc1(sw1, step):
    step("Verifying kernel interfaces if they are 'UP' for"
         " 'no shutdown' case and vice-versa")
    VRF_ID = create_vrf_and_get_vrf_UUID(sw1, "blue")
    step("Assigning ipv4 and ipv6 address to interface 3")
    sw1 ("config terminal")
    sw1("interface {}".format(sw1.ports["if03"]))
    sw1("vrf attach blue")
    sw1("ip address 12.1.1.1/8")
    sw1("ipv6 address 1000::1/120")
    step("Bringing interface 3 up")
    sw1("no shutdown")
    # sw1("exit")
    step("Verifying interface 3 'up' in the kernel")
    output = sw1("ip netns exec "+VRF_ID+" ifconfig 3", shell='bash')
    output = output.split()
    indexval = output.index("BROADCAST")
    assert 'UP' in output[indexval - 1]
    step("Verifying interface 3 ipv4 and ipv6 addresses in the kernel"
         " after 'no shut'")
    output = sw1("ip netns exec "+VRF_ID+" ip addr show 3", shell='bash')
    assert 'inet 12.1.1.1/8' in output
    assert 'inet6 1000::1/120' in output
    step("Bringing interface 3 down")
    sw1("shutdown")
    step("Verifying interface 3 'down' in the kernel")
    output = sw1("ip netns exec "+VRF_ID+" ifconfig 3", shell='bash')
    output = output.split()
    indexval = output.index("BROADCAST")
    assert "UP" not in output[indexval - 1]
    step("Verifying interface 3 ipv4 address in the kernel after 'shut'")
    output = sw1("ip netns exec "+VRF_ID+" ip addr show 3", shell='bash')
    assert 'inet 12.1.1.1/8' in output
    step("Bringing interface 3 up again")
    sw1("no shutdown")
    sw1("exit")
    step("Re-verifying interface 3 ipv4 and ipv6 addresses in the kernel"
         " after 'no shut'")
    output = sw1("ip netns exec "+VRF_ID+" ip addr show 3", shell='bash')
    assert 'inet 12.1.1.1/8' in output

# Test Case 2:
# Test case checks if the interfaces are UP in the kernel after
# "no shutdown" and vice-versa with default vrf. Also, it verifies
# that the kernel retains ipv4/ipv6 addresses after "no shutdown"
# with default vrf
def portd_functionality_tc2(sw1, step):
    step("Verifying kernel interfaces if they are 'UP' for"
         " 'no shutdown' case and vice-versa")
    VRF_ID = create_vrf_and_get_vrf_UUID(sw1, "blue")
    step("Assigning ipv4 and ipv6 address to interface 3")
    sw1("config terminal")
    sw1("interface {}".format(sw1.ports["if03"]))
    sw1("no vrf attach blue")
    sw1("ip address 12.1.1.1/8")
    sw1("ipv6 address 1000::1/120")
    step("Bringing interface 3 up")
    sw1("no shutdown")
    # sw1("exit")
    step("Verifying interface 3 'up' in the kernel")
    output = sw1("ip netns exec swns ifconfig 3", shell='bash')
    output = output.split()
    indexval = output.index("BROADCAST")
    assert 'UP' in output[indexval - 1]
    step("Verifying interface 3 ipv4 and ipv6 addresses in the kernel"
         " after 'no shut'")
    output = sw1("ip netns exec swns ip addr show 3", shell='bash')
    assert 'inet 12.1.1.1/8' in output
    assert 'inet6 1000::1/120' in output
    step("Bringing interface 3 down")
    sw1("shutdown")
    step("Verifying interface 3 'down' in the kernel")
    output = sw1("ip netns exec swns ifconfig 3", shell='bash')
    output = output.split()
    indexval = output.index("BROADCAST")
    assert "UP" not in output[indexval - 1]
    step("Verifying interface 3 ipv4 address in the kernel after 'shut'")
    output = sw1("ip netns exec swns ip addr show 3", shell='bash')
    assert 'inet 12.1.1.1/8' in output
    step("Bringing interface 3 up again")
    sw1("no shutdown")
    sw1("exit")
    step("Re-verifying interface 3 ipv4 and ipv6 addresses in the kernel"
         " after 'no shut'")
    output = sw1("ip netns exec swns ip addr show 3", shell='bash')
    assert 'inet 12.1.1.1/8' in output


# Test Case 3:
# Test case checks if the interfaces MTU is set kernel after
# configuring through CLI.
# Also checks MTU remains unchanged when invalid MTU is configured.
def portd_functionality_tc3(sw1, step):
    step("Assigning MTU values to kernel interfaces")
    VRF_ID = create_vrf_and_get_vrf_UUID(sw1, "blue")
    output = sw1("get subsystem base other_info:max_transmission_unit",
                 shell='vsctl')
    mtu_max = int(output.split('\"')[1])
    mtu_valid = mtu_max - 100
    mtu_invalid = mtu_max + 100
    sw1("config terminal")
    sw1("interface {}".format(sw1.ports["if03"]))
    output = sw1("no shutdown")
    output = sw1("vrf attach blue")
    output = sw1("mtu {}".format(mtu_valid))
    output = sw1("exit")
    step("Verifying interface 3 'MTU' value in the kernel")
    output = sw1("ip netns exec "+VRF_ID+" ifconfig 3", shell='bash')
    mtu = int(search('\d+', search('MTU:\d+', output).group()).group())
    assert mtu == mtu_valid
    sw1("config terminal")
    sw1("interface {}".format(sw1.ports["if03"]))
    output = sw1("no shutdown")
    output = sw1("mtu {}".format(mtu_invalid))
    output = sw1("exit")
    step("Verifying interface 3 with invalid 'MTU' value in the kernel")
    output = sw1("ip netns exec "+VRF_ID+" ifconfig 3", shell='bash')
    mtu = int(search('\d+', search('MTU:\d+', output).group()).group())
    assert mtu == mtu_valid


def verify_interface_netlink_in_ns(sw, intf_name, vrf_name, present):
    vrf_uuid = get_vrf_uuid(sw, vrf_name)
    output = sw("ip netns exec "+vrf_uuid+" ip -d link show "+intf_name,
                shell='bash')
    if(present):
        assert "does not exist" not in output, "The interface is expected \
            to be present."
    else:
        assert "does not exist" in output, "The interface is expected \
            to be absent in the namespace."


def move_interface_to_vrf_and_configure_ip(sw, intf_name, vrf_name, ip_address):
    sw("config terminal")
    sw("interface "+intf_name)
    sw("vrf attach "+vrf_name)
    sw("ip add "+ip_address)
    sw("end")


def move_interface_to_vrf(sw, intf_name, vrf_name):
    sw("config terminal")
    sw("interface "+intf_name)
    sw("vrf attach "+vrf_name)
    sw("end")


def get_ifindex(sw, intf_name, vrf_name):
    vrf_uuid = get_vrf_uuid(sw, vrf_name)
    output = sw("ip netns exec "+vrf_uuid+" ip -d link show "+intf_name,
                shell='bash')
    output = output.split()
    ifindex = re.sub(':', '', output[0])
    return ifindex


def get_interface_up(sw, intf_name):
    sw("config terminal")
    sw("interface "+intf_name)
    sw("no shutdown")
    sw("end")


# Testcase to verify the dummy interface creation and kernel interface
# movements between VRF for loopback creation and movement between VRF.
def portd_loopback_vrf_functionality_tc(sw1, step):
    VRF_BLUE_ID = create_vrf_and_get_vrf_UUID(sw1, "blue")
    VRF_RED_ID = create_vrf_and_get_vrf_UUID(sw1, "red")
    loopback_interface_name = "loopback3"

    step("Initial config for the loopback")
    sw1("config terminal")
    sw1("interface loopback 3")
    sw1("ip add 20.0.0.2/24")
    sw1("ipv6 address 1000::1/120")
    sw1("end")

    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "vrf_default", True)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "blue", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "red", False)

    # Verify the IPv4 and IPv6 address configured for the loopback interface.
    output = sw1("ip netns exec swns ip addr show loopback3", shell='bash')
    assert 'inet 20.0.0.2/24' in output
    assert 'inet6 1000::1/120' in output

    # Get the Ifindex of the interface.
    Ifindex_in_swns = get_ifindex(sw1, loopback_interface_name, "vrf_default")

    # Delete the ip address and verify.
    sw1("config terminal")
    sw1("interface loopback 3")
    sw1("no ip add 20.0.0.2/24")
    sw1("no ipv6 address 1000::1/120")
    sw1("end")

    output = sw1("ip netns exec swns ip addr show loopback3", shell='bash')
    assert 'inet 20.0.0.2/24' not in output
    assert 'inet6 1000::1/120' not in output

    step("Move the interface to VRF red and configure IP")
    sw1("config terminal")
    sw1("interface loopback 3")
    sw1("vrf attach red")
    sw1("ip add 20.0.0.2/24")
    sw1("ipv6 address 1000::1/120")
    sw1("end")

    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "vrf_default", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "blue", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "red", True)

    # Verify the IPv4 and IPv6 address configured for the loopback interface.
    output = sw1("ip netns exec "+VRF_RED_ID+" ip addr show loopback3", shell='bash')
    assert 'inet 20.0.0.2/24' in output
    #assert 'inet6 1000::1/120' in output

    Ifindex_in_vrf_red = get_ifindex(sw1, loopback_interface_name, "red")
    assert (Ifindex_in_swns == Ifindex_in_vrf_red)

    # Delete the ip address and verify.
    sw1("config terminal")
    sw1("interface loopback 3")
    sw1("no ip add 20.0.0.2/24")
    sw1("no ipv6 address 1000::1/120")
    sw1("end")

    output = sw1("ip netns exec "+VRF_RED_ID+" ip addr show loopback3", shell='bash')
    assert 'inet 20.0.0.2/24' not in output
    assert 'inet6 1000::1/120' not in output

    step("Move the interface to VRF blue ")
    move_interface_to_vrf(sw1, loopback_interface_name, "blue")

    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "vrf_default", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "blue", True)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "red", False)

    Ifindex_in_vrf_blue = get_ifindex(sw1, loopback_interface_name, "blue")
    assert (Ifindex_in_swns == Ifindex_in_vrf_blue)

    step("Delete the loopback interface")
    sw1("config terminal")
    sw1("no interface loopback 3")
    sw1("end")

    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "vrf_default", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "blue", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "red", False)


def portd_loopback_vrf_ping_functionality_tc(topology, step):
    sw1 = topology.get("sw1")
    sw2 = topology.get("sw2")
    assert sw1 is not None
    assert sw2 is not None
    VRF_BLUE_ID = create_vrf_and_get_vrf_UUID(sw1, "blue")
    VRF_RED_ID = create_vrf_and_get_vrf_UUID(sw1, "red")
    loopback_interface_name = "loopback3"

    step("Initial config for the loopback in sw2")
    sw2("config terminal")
    sw2("interface 1")
    sw2("ip add 20.0.0.1/24")
    sw2("no shutdown")
    sw2("exit")
    sw2("ip route 30.0.0.0/24 20.0.0.2")
    sw2("end")

    step("Initial config for the loopback in sw1")
    sw1("config terminal")
    sw1("interface 1")
    sw1("ip add 20.0.0.2/24")
    sw1("no shutdown")
    sw1("exit")
    sw1("interface loopback 3")
    sw1("ip add 30.0.0.2/24")
    sw1("end")

    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "vrf_default", True)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "blue", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "red", False)

    print("Ping s1 from s2\n")
    ping = sw2.libs.vtysh.ping('30.0.0.2', count=5)
    assert ping['transmitted'] == ping['received'] == 5

    step("Move loopback interface to VRf red.")
    move_interface_to_vrf_and_configure_ip(sw1, loopback_interface_name, "red", "30.0.0.2/24")

    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "vrf_default", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "blue", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "red", True)

    print("Ping s1 from s2\n")
    ping = sw2.libs.vtysh.ping('30.0.0.2', count=5)
    assert ping['received'] == 0, "Ping should fail as interface 1 is not part of vrf"

    step("Move connected interface to VRf red.")
    move_interface_to_vrf_and_configure_ip(sw1, "1", "red", "20.0.0.2/24")

    verify_interface_netlink_in_ns(sw1, "1", "vrf_default", False)
    verify_interface_netlink_in_ns(sw1, "1", "blue", False)
    verify_interface_netlink_in_ns(sw1, "1", "red", True)

    print("Ping s1 from s2\n")
    ping = sw2.libs.vtysh.ping('30.0.0.2', count=5)
    assert ping['transmitted'] == ping['received'] == 5

    step("Move loopback interface to VRf blue.")
    move_interface_to_vrf_and_configure_ip(sw1, loopback_interface_name, "blue", "30.0.0.2/24")

    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "vrf_default", False)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "blue", True)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "red", False)

    print("Ping s1 from s2\n")
    ping = sw2.libs.vtysh.ping('30.0.0.2', count=5)
    assert ping['received'] == 0, "Ping should fail as interface 1 is not part of vrf"

    step("Move connected interface to VRf blue.")
    move_interface_to_vrf_and_configure_ip(sw1, "1", "blue", "20.0.0.2/24")

    verify_interface_netlink_in_ns(sw1, "1", "vrf_default", False)
    verify_interface_netlink_in_ns(sw1, "1", "blue", True)
    verify_interface_netlink_in_ns(sw1, "1", "red", False)

    print("Ping s1 from s2\n")
    ping = sw2.libs.vtysh.ping('30.0.0.2', count=5)
    assert ping['transmitted'] == ping['received'] == 5

    step("Move back the connected interface and loopback to dafault by deleting the VRF.")
    sw1("config terminal")
    sw1("no vrf blue")
    sw1("interface 1")
    sw1("ip add 20.0.0.2/24")
    sw1("exit")
    sw1("interface loopback 3")
    sw1("ip add 30.0.0.2/24")
    sw1("end")

    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "vrf_default", True)
    verify_interface_netlink_in_ns(sw1, loopback_interface_name, "red", False)
    verify_interface_netlink_in_ns(sw1, "1", "vrf_default", True)
    verify_interface_netlink_in_ns(sw1, "1", "red", False)

    print("Ping s1 from s2\n")
    ping = sw2.libs.vtysh.ping('30.0.0.2', count=5)
    assert ping['transmitted'] == ping['received'] == 5


@pytest.mark.skipif(True, reason="Disabling due to VRF macro not enabled")
def test_portd_ct_functionality(topology, step):
    sw1 = topology.get("sw1")
    assert sw1 is not None
    portd_functionality_tc1(sw1, step)
    portd_functionality_tc2(sw1, step)
    portd_functionality_tc3(sw1, step)
    portd_loopback_vrf_functionality_tc(sw1, step)
    portd_loopback_vrf_ping_functionality_tc(topology, step)
