# -*- coding: utf-8 -*-

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

#
# This is a set of helper functions common to the tests in the layer 3 folder
#
# Note: these functions expect a 'name' attribute on the switch and host
#       objects that the framework does not provide, so it must be added
#       within the test before calling these functions
#
from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from ipaddress import ip_address


def switch_cfg_iface(switch, port_lbl, ipv4, ipv6):
    """
    Configure and enable a switch interface

    :param CommonNode switch: the switch to configure
    :param str port_lbl: the port label of the interface to configure
    :param str ipv4: the IPv4 address/mask to use (X.X.X.X/M)
    :param str ipv6: the IPv6 address/mask to use (X:X::X:X/M)
    """

    header = 'Configuring switch {0} port {1} with addresses {2} and {3}'
    print(header.format(switch.identifier, port_lbl, ipv4, ipv6))
    with switch.libs.vtysh.ConfigInterface(switch.ports[port_lbl]) as ctx:
        ctx.ip_address(ipv4)
        ctx.ipv6_address(ipv6)
        ctx.no_shutdown()


def switch_add_vlan(switch, vlan_id):
    """
    Add a vlan on a switch

    :param CommonNode switch: the switch to configure
    :param vlan_id: the vlan id
    """

    header = 'Adding Vlan {0} to switch {1}'
    print(header.format(vlan_id, switch.identifier))
    with switch.libs.vtysh.ConfigVlan(vlan_id) as ctx:
        ctx.no_shutdown()


def switch_add_vlan_port(switch, vlan_id, port_lbl):
    """
    Add and enable an interface to a vlan on a switch

    :param CommonNode     while True:
    sleep(10)switch: the switch to configure
    :param vlan_id: the vlan id
    :param str port_lbl: the port label of the interface to configure
    """

    header = 'Add switch {0} port {1} to vlan {2}'
    print(header.format(switch.identifier, port_lbl, vlan_id))
    with switch.libs.vtysh.ConfigInterface(switch.ports[port_lbl]) as ctx:
        ctx.no_routing()
        ctx.no_shutdown()
        ctx.vlan_access(vlan_id)


def switch_cfg_vlan(switch, vlan_id, ipv4, ipv6):
    """
    Configure and enable a switch vlan interface

    :param CommonNode switch: the switch to configure
    :param vlan_id: the vlan id
    :param str ipv4: the IPv4 address/mask to use (X.X.X.X/M)
    :param str ipv6: the IPv6 address/mask to use (X:X::X:X/M)
    """

    header = 'Configuring switch {0} vlan {1} with addresses {2} and {3}'
    print(header.format(switch.identifier, vlan_id, ipv4, ipv6))
    with switch.libs.vtysh.ConfigInterfaceVlan(vlan_id) as ctx:
        ctx.ip_address(ipv4)
        ctx.ipv6_address(ipv6)
        ctx.no_shutdown()


def switch_remove_interface_vlan(switch, vlan_id):
    """
    remove a switch vlan interface

    :param CommonNode switch: the switch to configure
    :param vlan_id: the vlan id
    """

    header = 'Un-Configuring switch {0} interface vlan {1}'
    print(header.format(switch.identifier, vlan_id))
    with switch.libs.vtysh.Configure() as ctx:
        ctx.no_interface_vlan(vlan_id)


def host_cfg_iface(host, port_lbl, ipv4, ipv6):
    """
    Configure and enable a Host interface

    :param CommonNode host: the host to configure
    :param str port_lbl: the port label of the interface to configure
    :param str ipv4: the IPv4 address/mask to use (X.X.X.X/M)
    :param str ipv6: the IPv6 address/mask to use (X:X::X:X/M)
    """

    header = 'Configuring host {0} port {1} with addresses {2} and {3}'
    print(header.format(host.identifier, port_lbl, ipv4, ipv6))
    host.libs.ip.interface(port_lbl, addr=ipv4, up=True)
    host.libs.ip.interface(port_lbl, addr=ipv6)


def host_add_route(host, dest_subnet, via):
    """
    Configure a static route on a host

    :param CommonNode host: the host to configure
    :param str dest_subnet: X.X.X.X/M IPv4 or X:X::X:X/M IPv6 dest prefix
    :param str via: X.X.X.X IPv4 or X:X::X:X IPv6 of the gateway
    """

    header = 'Adding host {0} static route to {1} via {2}'
    print(header.format(host.identifier, dest_subnet, via))
    host.libs.ip.add_route(dest_subnet, via)


def host_ping_expect_success(pings, host, dest, dest_ip):
    """
    Send a ping from the given host and check verify success

    :param CommonNode host: the host to sent ping from
    :param CommonNode dest: the destination node
    :param str dest_ip: X.X.X.X IPv4 or X:X::X:X IPv6 of the destination
    """

    header = 'Ping {0} from {1}: expect success'
    print(header.format(dest.identifier, host.identifier))

    png = host.libs.ping.ping(pings, dest_ip)
    assert png['received'] > 0, 'Ping Failed\n'

    png = host.libs.ping.ping(pings, dest_ip)
    assert png['transmitted'] == png['received'] == pings, 'Ping Failed\n'


def host_ping_expect_failure(pings, host, dest, dest_ip):
    """
    Send a ping from the given host and check verify failure

    :param CommonNode host: the host to sent ping from
    :param CommonNode dest: the destination node
    :param str dest_ip: X.X.X.X IPv4 or X:X::X:X IPv6 of the destination
    """

    header = 'Ping {0} from {1}: expect failure'
    print(header.format(dest.identifier, host.identifier))
    png = host.libs.ping.ping(pings, dest_ip)
    assert png['received'] == 0, 'Ping Successful\n'
