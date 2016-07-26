# -*- coding: utf-8 -*-
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
# |  hsw1  <----->  sw1  |
# |       |     +-------+
# +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host name="Host 1"] hsw1

# Links
hsw1:if01 -- sw1:if01
"""


def test_portd_ct_admin_state(topology, step):
    first_interface = "1"
    port_down = 'enable="false"'
    port_up = 'enable="true"'
    sw1 = topology.get("sw1")
    # step('Test portd admin state changes for L3 interfaces')
    step('1-Configuring the topology')
    # Configure switch sw1
    sw1("configure terminal")
    # Configure interface 1 on switch sw1
    sw1("interface 1")
    sw1("ip address 10.0.10.1/24")
    sw1("ipv6 address 2000::1/120")
    sw1("end")
    # Verify the port and interface is created with same name for L3 port
    step('2-Verify port and interface is created with same name for L3 port')
    cmd = "get interface {first_interface} name".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert first_interface in output
    cmd = "get port {first_interface} name".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert first_interface in output
    step('3-Verify port and interface is created'
         'with same name VLAN interface')
    cmd = "get interface {first_interface} name".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert first_interface in output
    cmd = "get port {first_interface} name".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert first_interface in output
    # Verify the port hw_config is down and interface is down by default
    step('4-Verify the port is down by default')
    cmd = "get port {first_interface} hw_config".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert port_down in output
    step('5-Verify port is up on no shut and goes down when port is disabled')
    sw1("configure terminal")
    sw1("interface 1")
    sw1("no shutdown")
    sw1("end")
    cmd = "get port {first_interface} hw_config".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert port_up in output
    # Change the admin state of port to down
    cmd = "set port {first_interface} admin=down".format(**locals())
    sw1(cmd, shell='vsctl')
    cmd = "get port {first_interface} admin".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert "down" in output
    cmd = "get port {first_interface} hw_config".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert port_down in output
    step('6-Verify port hw_config is set to false when interface '
         'user_config is down for L3 and VLAN interfaces')
    sw1("configure terminal")
    sw1("interface 1")
    sw1("no shutdown")
    sw1("end")
    cmd = "get port {first_interface} hw_config".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert port_up in output
    # Change the user_config of interface to down
    sw1("set interface {first_interface} "
        "user_config:admin=down".format(**locals()),
        shell='vsctl')
    # Verify the port is down
    cmd = "get port {first_interface} hw_config".format(**locals())
    output = sw1(cmd, shell='vsctl')
    assert port_down in output
