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
# |  hs1  <----->  sw1  |
# |       |     +-------+
# +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host name="Host 1"] hs1

# Links
hs1:if01 -- sw1:if01
"""


def test_portd_ct_connected_routes(topology, step):
    sw1 = topology.get("sw1")
    step('1-Test portd addition of the connected routes')
    sw1("set interface 1 user_config:admin=up", shell='vsctl')
    sw1("set interface 2 user_config:admin=up", shell='vsctl')
    # Configure switch sw1
    sw1("configure terminal")
    # Configure interface 1 on switch sw1
    sw1("interface 1")
    sw1("ip address 10.0.10.1/24")
    sw1("ipv6 address 2000::1/120")
    sw1("exit")
    # Configure interface 2 on switch sw1
    sw1("interface 2")
    sw1("ip address 10.0.20.1/24")
    sw1("ipv6 address 2001::1/120")
    sw1("exit")
    step('2-Verify connected routes are present in db')
    # Parse the "ovsdb-client dump" output and extract the lines between
    # "Route table" and "Route_Map table". This section will have all the
    # Route table entries. Then parse line by line to match the contents
    dump = sw1("ovsdb-client dump", shell='bash')
    lines = dump.split('\n')
    check = False
    count = 0
    for line in lines:
        if check:
            if 'connected' in line and 'unicast' in line and \
               '10.0.10.0/24' in line and 'true' in line:
                count += 1
            elif 'connected' in line and 'unicast' in line and \
                 '10.0.20.0/24' in line and 'true' in line:
                count += 1
            elif 'connected' in line and 'unicast' in line and \
                 '2000::/120' in line and 'true' in line:
                count += 1
            elif 'connected' in line and 'unicast' in line and \
                 '2001::/120' in line and 'true' in line:
                count += 1
        if 'Route table' in line:
            check = True
        if 'Route_Map table' in line:
            check = False
    assert count is 4
