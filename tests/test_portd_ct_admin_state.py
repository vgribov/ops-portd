#!/usr/bin/python

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

from opsvsi.docker import *
from opsvsi.opsvsitest import *

first_interface = "1"
second_interface = "2"
third_interface = "3"
fourth_interface = "4"
lag_interface = "lag1"

interface_down_string = "enable=false"
interface_up_string = "enable=true"
port_down = "enable=false"
port_up = "enable=true"

class adminstateupdateCTTest( OpsVsiTest ):

    def setupNet(self):
        self.net = Mininet(topo=SingleSwitchTopo(k=0, hopts=self.getHostOpts(),
                                                 sopts=self.getSwitchOpts()),
                           switch=VsiOpenSwitch,
                           host=OpsVsiHost,
                           link=OpsVsiLink, controller=None,
                           build=True)

    def test_port_interface_admin_state(self):
        info('\n########## Test portd admin state changes for L3'\
             ' interfaces ##########\n');
        info('\n### Configuring the topology ###\n')
        s1 = self.net.switches[ 0 ]

        # Configure switch s1
        s1.cmdCLI("configure terminal")

        # Configure interface 1 on switch s1
        s1.cmdCLI("interface 1")
        s1.cmdCLI("ip address 10.0.10.1/24")
        s1.cmdCLI("ipv6 address 2000::1/120")
        s1.cmdCLI("exit")

        # Verify the port and interface is created with same name for L3 port
        info('###### Verify the port and interface is created with'\
             ' same name for L3 port ######\n')
        cmd = "/usr/bin/ovs-vsctl get interface %s name" % first_interface
        output = s1.ovscmd(cmd)
        assert first_interface in output, 'Failed to create interface 1'
        cmd = "/usr/bin/ovs-vsctl get port %s name" % first_interface
        output = s1.ovscmd(cmd)
        assert first_interface in output, 'Failed to create port 1'
        info('### Port and interface 1 created successfully ###\n');

        # Verify the port and interface is created with same name for VLAN interface
        info('###### Verify the port and interface is created with'\
             ' same name VLAN interface ######\n')
        cmd = "/usr/bin/ovs-vsctl get interface %s name" % first_interface
        output = s1.ovscmd(cmd)
        assert first_interface in output, 'Failed to create interface 1'
        cmd = "/usr/bin/ovs-vsctl get port %s name" % first_interface
        output = s1.ovscmd(cmd)
        assert first_interface in output, 'Failed to create port 1'
        info('### Port and interface 1 created successfully ###\n');

        # Verify the port hw_config is down and interface is down by default
        info('##### Verify the port is down by'\
             ' default ####\n')
        cmd = "/usr/bin/ovs-vsctl get port %s hw_config" % first_interface
        output = s1.ovscmd(cmd)
        assert port_down in output, 'Incorrect port default state'
        info('### Default state of port is down as expected ###\n');

        # Verify the interface associated with the port goes down when port is disabled
        info('##### Verify port is up on no shut and'\
             ' goes down when port is disabled #####\n')
        s1.cmdCLI("configure terminal")
        s1.cmdCLI("interface 1")
        s1.cmdCLI("no shutdown")
        s1.cmdCLI("exit")
        cmd = "/usr/bin/ovs-vsctl get port %s hw_config" % first_interface
        output = s1.ovscmd(cmd)
        assert port_up in output, 'Port state is set to down'
        # Change the admin state of port to down
        cmd = "/usr/bin/ovs-vsctl set port %s admin=down" % first_interface
        s1.ovscmd(cmd)
        cmd = "/usr/bin/ovs-vsctl get port %s admin" % first_interface
        output = s1.ovscmd(cmd)
        assert "down" in output, 'Port state remains up'
        cmd = "/usr/bin/ovs-vsctl get port %s hw_config" % first_interface
        output = s1.ovscmd(cmd)
        assert port_down in output, 'Port state remains up'

        # Verify port hw_config is set to false when interface
        # user_config is down for L3 and VLAN interfaces
        info('###### Verify port hw_config is set to false when'\
             ' interface user_config is down for L3 and VLAN interfaces #####\n')
        s1.cmdCLI("configure terminal")
        s1.cmdCLI("interface 1")
        s1.cmdCLI("no shutdown")
        s1.cmdCLI("exit")
        cmd = "/usr/bin/ovs-vsctl get port %s hw_config" % first_interface
        output = s1.ovscmd(cmd)
        assert port_up in output, 'Port state is set to down'
        # Change the user_config of interface to down
        cmd = "/usr/bin/ovs-vsctl set interface %s user_config=admin=down" % first_interface
        s1.ovscmd(cmd)
        # Verify the port is down
        cmd = "/usr/bin/ovs-vsctl get port %s hw_config" % first_interface
        output = s1.ovscmd(cmd)
        assert port_down in output, 'Port state remains up'
        info('### Port state changed to down as the port is down ###\n');

@pytest.mark.skipif(True, reason="Disabling old tests")
class Test_portd_admin_state_update:

    def setup_class(cls):
        Test_portd_admin_state_update.test = adminstateupdateCTTest()

    def teardown_class(cls):
        # Stop the Docker containers, and
        # mininet topology
        Test_portd_admin_state_update.test.net.stop()

    def test_port_interface_admin_state(self):
        self.test.test_port_interface_admin_state()

    def __del__(self):
        del self.test
