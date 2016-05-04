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

TOPOLOGY = """
# +-------+
# |  sw1  |
# +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1

# Interfaces
sw1:if01
sw1:if02
sw1:if03
sw1:if04
"""

def getVrf_UUID(sw1):
    blue_vrf = None

    output = sw1("ovs-vsctl add-vrf blue", shell='bash')
    print ("Configured VRF blue")
    out = sw1("ip netns", shell='bash')
    lines = out.split('\n')
    for line in lines:
        if "nonet" not in line and "swns" not in line and " " not in \
                   line and "netns" not in line:
            blue_vrf = line.strip()
    print ("Created namespace "+blue_vrf+"")
    return blue_vrf


# Test Case 1:
# Test case checks if the interfaces are UP in the kernel after
# "no shutdown" and vice-versa with non default vrf. Also, it verifies
# that the kernel retains ipv4/ipv6 addresses after "no shutdown",
# with non default-vrf
def portd_functionality_tc1(sw1, step):
    step("Verifying kernel interfaces if they are 'UP' for"
         " 'no shutdown' case and vice-versa")
    VRF_ID = getVrf_UUID(sw1)
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
    VRF_ID = getVrf_UUID(sw1)
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
    VRF_ID = getVrf_UUID(sw1)
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


@pytest.mark.skipif(True, reason="Disabling due to VRF macro not enabled")
def test_portd_ct_functionality(topology, step):
    sw1 = topology.get("sw1")
    assert sw1 is not None
    portd_functionality_tc1(sw1, step)
    portd_functionality_tc2(sw1, step)
    portd_functionality_tc3(sw1, step)
