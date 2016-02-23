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
# Name:        test_portd_ct_linux_bonding_driver_configuration.py
#
# Objective:   Verify Linux bonding is configured properly when LAG are
#              created and deleted, also when interfaces are added and
#              removed.
#
# Topology:    2 switches (DUT running Halon) connected by 3 interfaces
#
##########################################################################

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
sw1:3 -- sw2:3
"""


def turn_on_interface(sw, intf):
    c = "set interface " + str(intf) + " user_config:admin=up"
    cmd_output = sw(c.format(**locals()), shell='vsctl')

    # If command returns '' that means the interface was successfully turned on
    assert cmd_output == '',\
        "Turn on interface: %s return: %s" % (intf, cmd_output)


# Create a bond/lag/trunk in the OVS-DB.
def sw_create_bond(sw, bond_name, intf_list):
    print("Creating LAG %s with interfaces: %s \n" %
          (bond_name, str(intf_list)))
    c = ("add-bond bridge_normal %s %s -- set port %s lacp=off" %
         (bond_name, " ".join(map(str, intf_list)), bond_name))
    cmd_output = sw(c.format(**locals()), shell='vsctl')

    # If command returns '' that means the lag was succesfully created
    assert cmd_output == '',\
        "Create bond: %s return: %s" % (bond_name, cmd_output)


# Delete a bond/lag/trunk from OVS-DB.
def sw_delete_bond(sw, bond_name):
    print("Deleting the bond %s \n" % (bond_name))
    c = ("del-port bridge_normal %s" % (bond_name))
    cmd_output = sw(c.format(**locals()), shell='vsctl')

    # If command returns '' that means the lag was succesfully deleted
    assert cmd_output == '',\
        "Delete bond: %s return: %s" % (bond_name, cmd_output)


# Add a new Interface to the existing bond.
def add_interface_to_bond(sw, bond_name, intf_name):

    print("Adding interface %s to LAG %s \n" %
          (intf_name, bond_name))
    # Get the UUID of the interface that has to be added.
    c = ("get interface %s _uuid" % (str(intf_name)))

    intf_uuid = sw(c.format(**locals()), shell='vsctl').rstrip('\r\n')

    # Get the current list of Interfaces in the bond.
    c = ("get port %s interfaces" % (bond_name))
    out = sw(c.format(**locals()), shell='vsctl')
    intf_list = out.rstrip('\r\n').strip("[]").replace(" ", "").split(',')

    assert intf_uuid not in intf_list,\
        print("Interface %s is already part of %s \n" %
              (intf_name, bond_name))

    # Add the given intf_name's UUID to existing Interfaces.
    intf_list.append(intf_uuid)

    # Set the new Interface list in the bond.
    new_intf_str = "[%s]" % (",".join(intf_list))

    c = ("set port %s interfaces=%s" % (bond_name, new_intf_str))
    sw(c.format(**locals()), shell='vsctl')


# Remove an Interface from a bond.
def remove_interface_from_bond(sw, bond_name, intf_name):

    print("Removing interface %s from LAG %s\n" % (intf_name, bond_name))

    # Get the UUID of the interface that has to be added.
    c = ("get interface %s _uuid" % (str(intf_name)))

    intf_uuid = sw(c.format(**locals()), shell='vsctl').rstrip('\r\n')

    # Get the current list of Interfaces in the bond.
    c = ("get port %s interfaces" % (bond_name))
    out = sw(c.format(**locals()), shell='vsctl')
    intf_list = out.rstrip('\r\n').strip("[]").replace(" ", "").split(',')

    assert intf_uuid in intf_list,\
        print("Unable to find the interface %s in the bond: %s" %
              (intf_name, bond_name))

    # Remove the given intf_name's UUID from the bond's Interfaces.
    new_intf_list = [i for i in intf_list if i != intf_uuid]

    # Set the new Interface list in the bond.
    new_intf_str = "[%s]" % (",".join(new_intf_list))

    c = ("set port %s interfaces=%s" % (bond_name, new_intf_str))
    sw(c.format(**locals()), shell='vsctl')


# Check if linux bond exists based on ifconfig output
def sw_is_linux_bond_created(sw, bond_name):
    cmd_output = sw('ifconfig'.format(**locals()),
                    shell='bash_swns')
    lines = cmd_output.split('\n')
    for line in lines:
        if bond_name in line:
            return True
    return False


# Check if a given interface is part of the slaves of a given bond
def sw_is_interface_in_bond(sw, bond_name, intf_name):
    c = ("cat /sys/class/net/%s/bonding/slaves" % (bond_name))
    cmd_output = sw(c.format(**locals()), shell='bash_swns')

    if intf_name in cmd_output:
            return True
    return False


def test_lag_linux_bond_configuration(topology):
    """
    Case 1:
        Verify Linux bonding drivers files are configured
        correctly when LAG is created/deleted and when
        interfaces are added/removed.
    """
    sw1 = topology.get('sw1')
    sw2 = topology.get('sw2')
    sw1_lag_name = 'lag1'
    sw2_lag_name = 'lag2'

    assert sw1 is not None
    assert sw2 is not None

    p11 = sw1.ports['1']
    p12 = sw1.ports['2']
    p13 = sw1.ports['3']
    p21 = sw2.ports['1']
    p22 = sw2.ports['2']
    p23 = sw2.ports['3']

    # Initial interfaces for each lag
    ports_lag_sw1 = [p11, p12]
    ports_lag_sw2 = [p21, p22]

    print("Turning on all interfaces used in this test")
    ports_sw1 = [p11, p12, p13]
    for port in ports_sw1:
        turn_on_interface(sw1, port)

    ports_sw2 = [p21, p22, p23]
    for port in ports_sw2:
        turn_on_interface(sw2, port)

    # Create LAG in both switches
    sw_create_bond(sw1, sw1_lag_name, ports_lag_sw1)
    sw_create_bond(sw2, sw2_lag_name, ports_lag_sw2)

    # Verify if Linux bond has been created for each LAG
    assert sw_is_linux_bond_created(sw1, sw1_lag_name),\
        "Linux Bonding for %s should be created" % (sw1_lag_name)
    assert sw_is_linux_bond_created(sw2, sw2_lag_name),\
        "Linux Bonding for %s should be created" % (sw2_lag_name)

    # Add interfaces to each LAG
    ports_lag_sw1.append(p13)
    ports_lag_sw2.append(p23)
    add_interface_to_bond(sw1, sw1_lag_name, p13)
    add_interface_to_bond(sw2, sw2_lag_name, p23)

    # Verify the interfaces were added to the linux bond
    for interface in ports_lag_sw1:
        assert sw_is_interface_in_bond(sw1, sw1_lag_name, interface),\
            ("Interface %s should be part of bond: %s" %
             (interface, sw1_lag_name))
    for interface in ports_lag_sw2:
        assert sw_is_interface_in_bond(sw2, sw2_lag_name, interface),\
            ("Interface %s should be part of bond: %s" %
             (interface, sw2_lag_name))

    # Remove interfaces from each LAG
    remove_interface_from_bond(sw1, sw1_lag_name, p11)
    remove_interface_from_bond(sw2, sw2_lag_name, p22)

    # Verify the interface was removed from the linux bond
    assert not sw_is_interface_in_bond(sw1, sw1_lag_name, p11),\
        ("Interface %s should not be part of bond: %s" %
         (p11, sw1_lag_name))
    assert not sw_is_interface_in_bond(sw2, sw2_lag_name, p22),\
        ("Interface %s should not be part of bond: %s" %
         (p22, sw2_lag_name))

    ports_lag_sw1.remove(p11)
    ports_lag_sw2.remove(p22)

    # Verify the remaining interfaces are still in the linux bond
    for interface in ports_lag_sw1:
        assert sw_is_interface_in_bond(sw1, sw1_lag_name, interface),\
            ("Interface %s should be part of bond: %s" %
             (interface, sw1_lag_name))
    for interface in ports_lag_sw2:
        assert sw_is_interface_in_bond(sw2, sw2_lag_name, interface),\
            ("Interface %s should be part of bond: %s" %
             (interface, sw2_lag_name))

    # Delete LAG in both switches
    sw_delete_bond(sw1, sw1_lag_name)
    sw_delete_bond(sw2, sw2_lag_name)

    assert not sw_is_linux_bond_created(sw1, sw1_lag_name),\
        "Linux Bonding for %s should be deleted" % (sw1_lag_name)
    assert not sw_is_linux_bond_created(sw2, sw2_lag_name),\
        "Linux Bonding for %s should be deleted" % (sw2_lag_name)
