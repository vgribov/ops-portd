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

##########################################################################
# Name:        test_portd_ft_l2_lag_bridge_normal.py
#
# Objective:   Verify Linux bonding port for L2 LAG is properly added
#              or remove from the bridge_normal. Also verify if L2 ports
#              added to the LAG are removed from bridge_normal.
#
# Topology:    2 switches (DUT running Halon) connected by 2 interfaces
#
##########################################################################

from time import sleep

TOPOLOGY = """
# +-------+     +-------+
# |  sw1  |-----|  sw2  |
# +-------+     +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=openswitch name="Switch 2"] sw2

# Links
sw1:1 -- sw2:1
sw1:2 -- sw2:2
"""


# Delete a bond/lag/trunk from OVS-DB.
def sw_delete_bond(sw, bond_name):
    print("Deleting the bond %s \n" % (bond_name))
    c = ("del-port bridge_normal %s" % (bond_name))
    cmd_output = sw(c.format(**locals()), shell="vsctl")

    # If command returns "" that means the lag was succesfully deleted
    assert cmd_output == "",\
        "Delete bond: %s return: %s" % (bond_name, cmd_output)


def associate_interface_to_lag(sw, interface, lag_id):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.lag(lag_id)
    lag_name = "lag" + lag_id
    output = sw.libs.vtysh.show_lacp_aggregates(lag_name)
    assert interface in output[lag_name]['interfaces'],\
        "Unable to associate interface to lag"


# Check if a given port is part of bridge_normal
def sw_is_port_in_bridge(sw, intf_name):
    c = "list-ports bridge_normal"
    cmd_output = sw(c.format(**locals()), shell="vsctl")
    lines = cmd_output.split('\n')
    for line in lines:
        if intf_name == line:
            return True
    return False


def turn_on_l2_interface(sw, interface):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.no_shutdown()
        ctx.no_routing()


def configure_l2_interface(sw, interface):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.no_routing()


def turn_off_interface(sw, interface):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.shutdown()


def validate_turn_on_interfaces(sw, interfaces):
    for intf in interfaces:
        output = sw.libs.vtysh.show_interface(intf)
        assert output["interface_state"] == "up",\
            "Interface state for " + intf + " is down"


def configure_l2_lag(sw, lag_id):
    with sw.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.no_routing()


def configure_l3_lag(sw, lag_id):
    with sw.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.routing()


def test_lag_bridge_normal_configuration(topology):
    """
    Case 1:
       Verify the interfaces in bridge_normal are properly updated
       according to the configuration of L2 LAGs and interfaces.
    """
    sw1 = topology.get("sw1")
    sw2 = topology.get("sw2")
    sw_lag_name = "lag50"
    sw_lag_id = "50"

    assert sw1 is not None
    assert sw2 is not None

    p11 = sw1.ports["1"]
    p12 = sw1.ports["2"]
    p21 = sw2.ports["1"]
    p22 = sw2.ports["2"]

    print("Turning on all interfaces used in this test")
    ports_sw1 = [p11, p12]
    for port in ports_sw1:
        turn_on_l2_interface(sw1, port)

    ports_sw2 = [p21, p22]
    for port in ports_sw2:
        turn_on_l2_interface(sw2, port)

    print("Waiting some time for the interfaces to be up")
    sleep(30)

    print("Verify all interface are up")
    validate_turn_on_interfaces(sw1, ports_sw1)
    validate_turn_on_interfaces(sw2, ports_sw2)

    print("Verify port 1 and 2 are part of bridge_normal")
    for port in ports_sw1:
        assert sw_is_port_in_bridge(sw1, port),\
            "Port %s should be part of bridge_normal" % (port)
    for port in ports_sw2:
        assert sw_is_port_in_bridge(sw2, port),\
            "Port %s should be part of bridge_normal" % (port)

    print("Create L2 LAG in both switches")
    configure_l2_lag(sw1, sw_lag_id)
    configure_l2_lag(sw2, sw_lag_id)

    print("Associate interfaces [1, 2] to L2 LAG in both switches")
    associate_interface_to_lag(sw1, p11, sw_lag_id)
    associate_interface_to_lag(sw1, p12, sw_lag_id)
    associate_interface_to_lag(sw2, p21, sw_lag_id)
    associate_interface_to_lag(sw2, p22, sw_lag_id)

    print("Verify LAGs are part of bridge_normal")
    assert sw_is_port_in_bridge(sw1, sw_lag_name),\
        "LAG %s should be part of bridge_normal" % (sw_lag_name)
    assert sw_is_port_in_bridge(sw2, sw_lag_name),\
        "LAG %s should be part of bridge_normal" % (sw_lag_name)

    print("Verify port 1 and 2 are not part of bridge_normal")
    for port in ports_sw1:
        assert not sw_is_port_in_bridge(sw1, port),\
            "Port %s should not be part of bridge_normal" % (port)
    for port in ports_sw2:
        assert not sw_is_port_in_bridge(sw2, port),\
            "Port %s should not be part of bridge_normal" % (port)

    print("Configure the LAG as a L3 LAG in both switches")
    configure_l3_lag(sw1, sw_lag_id)
    configure_l3_lag(sw2, sw_lag_id)

    print("Verify L3 LAGs are not part of bridge_normal")
    assert not sw_is_port_in_bridge(sw1, sw_lag_name),\
        "L3 LAG %s should not be part of bridge_normal" % (sw_lag_name)
    assert not sw_is_port_in_bridge(sw2, sw_lag_name),\
        "L3 LAG %s should not be part of bridge_normal" % (sw_lag_name)

    print("Configure the LAG as a L2 LAG in both switches")
    configure_l2_lag(sw1, sw_lag_id)
    configure_l2_lag(sw2, sw_lag_id)

    print("Verify LAGs are part of bridge_normal")
    assert sw_is_port_in_bridge(sw1, sw_lag_name),\
        "LAG %s should be part of bridge_normal" % (sw_lag_name)
    assert sw_is_port_in_bridge(sw2, sw_lag_name),\
        "LAG %s should be part of bridge_normal" % (sw_lag_name)

    print("Delete LAG in both switches")
    sw_delete_bond(sw1, sw_lag_name)
    sw_delete_bond(sw2, sw_lag_name)

    print("Verify deleted LAGs are not part of bridge_normal")
    assert not sw_is_port_in_bridge(sw1, sw_lag_name),\
        "LAG %s should not be part of bridge_normal" % (sw_lag_name)
    assert not sw_is_port_in_bridge(sw2, sw_lag_name),\
        "LAG %s should not be part of bridge_normal" % (sw_lag_name)

    print("Configure interfaces 1 and 2 as L2")
    ports_sw1 = [p11, p12]
    for port in ports_sw1:
        configure_l2_interface(sw1, port)

    ports_sw2 = [p21, p22]
    for port in ports_sw2:
        configure_l2_interface(sw2, port)

    print("Verify port 1 and 2 are part of bridge_normal now")
    for port in ports_sw1:
        assert sw_is_port_in_bridge(sw1, port),\
            "Port %s should be part of bridge_normal" % (port)
    for port in ports_sw2:
        assert sw_is_port_in_bridge(sw2, port),\
            "Port %s should be part of bridge_normal" % (port)
