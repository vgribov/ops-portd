# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
# GNU Zebra is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# GNU Zebra is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Zebra; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.


TOPOLOGY = """
# +-------+
# |       |     +-------+
# |  hs1  <----->  sw1  |
# |       |     +-------+
# +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host name="Host 1"] hs1

# Links
hs1:if01 -- sw1:if01
"""


def test_portd_ct_inter_vlan_interface(topology, step):
    sw1 = topology.get("sw1")
    assert sw1 is not None

    vlan_interface = "vlan10"
    step("1-Checking inter-VLAN interface creation")
    sw1("configure terminal")
    sw1("vlan 10")
    sw1("no shutdown")
    sw1("interface {vlan_interface}".format(**locals()))
    sw1("end")

    sw1("ip netns exec swns bash", shell='bash')
    return_ = sw1("ifconfig -a "
                  " {vlan_interface}".format(**locals()),
                  shell='bash')
    assert vlan_interface in return_

    step("2-Adding IPv4 address to inter-VLAN interface")
    ipv4 = "192.168.0.1/30"
    sw1("configure terminal")
    sw1("interface {vlan_interface}".format(**locals()))
    sw1("ip address {ipv4}".format(**locals()))
    sw1("end")

    return_ = sw1("ip addr show {vlan_interface}".format(**locals()),
                  shell='bash')
    assert ipv4 in return_

    step("3-Adding IPv6 address to inter-VLAN interface")
    ipv6 = "2000::1/120"
    sw1("configure terminal")
    sw1("interface {vlan_interface}".format(**locals()))
    sw1("ipv6 address {ipv6}".format(**locals()))
    sw1("end")

    return_ = sw1("ip addr show {vlan_interface}".format(**locals()),
                  shell='bash')
    assert ipv6 in return_

    step("4-Deliting IPv6 address from inter-VLAN interface")
    sw1("configure terminal")
    sw1("interface {vlan_interface}".format(**locals()))
    sw1("no ipv6 address {ipv6}".format(**locals()))
    sw1("end")

    return_ = sw1("ip addr show {vlan_interface}".format(**locals()),
                  shell='bash')
    assert ipv6 not in return_

    step("5-Inter-VLAN interface deletion")
    sw1("configure terminal")
    sw1("no interface {vlan_interface}".format(**locals()))
    sw1("end")

    sw1("ip netns exec swns bash", shell='bash')
    return_ = sw1("ifconfig -a {vlan_interface}".format(**locals()),
                  shell='bash')
    assert 'does not exist' in return_
