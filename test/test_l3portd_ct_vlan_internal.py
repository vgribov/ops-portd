#!/usr/bin/env python

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

from halonvsi.docker import *
from halonvsi.halon import *

first_interface = "10"
second_interface = "11"
third_interface = "12"
fourth_interface = "13"
fifth_interface = "14"
sixth_interface = "15"
seventh_interface = "16"

class vlanInternalCT( HalonTest ):

    def setupNet(self):
        self.net = Mininet(topo=SingleSwitchTopo(k=0,
                                                 hopts=self.getHostOpts(),
                                                 sopts=self.getSwitchOpts()),
                                                 switch=HalonSwitch,
                                                 host=HalonHost,
                                                 link=HalonLink, controller=None,
                                                 build=True)

    def test_vlan_internal_cli(self):
        '''
            Test VLAN internal CLI working
        '''
        info('\n########## Internal VLAN CLI validations ##########\n\n')
        s1 = self.net.switches[ 0 ]

        s1.cmdCLI("configure terminal")

        # Checking internal VLAN range at bootup
        info('### Checking Internal VLAN range at bootup ###\n')
        ret = s1.cmdCLI("do show vlan internal")
        assert 'Internal VLAN range  : 1024-4094' in ret and \
               'Internal VLAN policy : ascending' in ret, 'Internal ' \
               'VLAN range at bootup validation failed'
        info('### Internal VLAN range at bootup validation passed ###\n\n')

        # Checking invalid internal VLAN range
        info('### Checking Internal VLAN range with (start > end) ###\n')
        ret = s1.cmdCLI("vlan internal range 100 10 ascending")
        assert 'Invalid VLAN range. End VLAN must be greater or equal to start VLAN' \
               in ret, 'Internal VLAN range (start > end) validation failed'
        info('### Internal VLAN range (start > end) validation passed ###\n\n')

        # Checking equal start & end internal VLAN range
        info('### Checking Internal VLAN range with (start = end) ###\n')
        s1.cmdCLI("vlan internal range 10 10 ascending")
        ret = s1.cmdCLI("do show vlan internal")
        assert 'Internal VLAN range  : 10-10' in ret and \
               'Internal VLAN policy : ascending', 'Internal VLAN range ' \
               '(start = end) validation failed'
        info('### Internal VLAN range (start = end) validation passed ###\n\n')

        # Checking ascending internal VLAN range
        info('### Checking Ascending Internal VLAN range ###\n')
        s1.cmdCLI("vlan internal range 10 100 ascending")
        ret = s1.cmdCLI("do show vlan internal")
        assert 'Internal VLAN range  : 10-100' in ret and \
               'Internal VLAN policy : ascending' in ret, \
               'Ascending Internal VLAN range validation failed'
        info('### Ascending Internal VLAN range validation passed ###\n\n')

        # Checking descending internal VLAN range
        info('### Checking Descending Internal VLAN range ###\n')
        s1.cmdCLI("vlan internal range 100 200 descending")
        ret = s1.cmdCLI("do show vlan internal")
        assert 'Internal VLAN range  : 100-200' in ret and \
               'Internal VLAN policy : descending' in ret, \
               'Descending Internal VLAN range validation failed'
        info('### Descending Internal VLAN range validation passed ###\n\n')

        # Checking default internal VLAN range
        info('### Checking Default Internal VLAN range ###\n')
        s1.cmdCLI("no vlan internal range")
        ret = s1.cmdCLI("do show vlan internal")
        assert 'Internal VLAN range  : 1024-4094' in ret and \
               'Internal VLAN policy : ascending' in ret, \
               'Default Internal VLAN range validation failed'
        info('### Default Internal VLAN range validation passed ###\n\n')

        #Cleanup
        s1.cmdCLI("exit")
        info('########## Internal VLAN CLI validations passed ##########\n\n')

    def test_vlan_internal_functionality(self):
        '''
            Test internal VLAN functionality
        '''
        info('\n########## Checking Internal VLAN functionality ##########\n\n')
        s1 = self.net.switches[ 0 ]

        s1.cmdCLI("configure terminal")
        info('### Running the command "vlan internal range 400 500 ' \
             'ascending" ###\n')
        s1.cmdCLI("vlan internal range 400 500 ascending")
        # Adding multiple interfaces to check internal vlan working
        intf_cmd = "interface " + first_interface
        s1.cmdCLI(intf_cmd)
        s1.cmdCLI("ip address 10.1.1.1/8")
        s1.cmdCLI("exit")
        intf_cmd = "interface " + second_interface
        s1.cmdCLI(intf_cmd)
        s1.cmdCLI("ip address 10.1.1.2/8")
        s1.cmdCLI("exit")
        ret = s1.cmdCLI("do show vlan internal")
        output = ret.split('\n')
        for line in output:
            if '\t' + first_interface in line:
                vlan_output = line.strip().split('\t')
                vlan_intf1 = int(vlan_output[0])
            if '\t' + second_interface in line:
                vlan_output = line.strip().split('\t')
                vlan_intf2 = int(vlan_output[0])
        assert 'Internal VLAN range  : 400-500' in output and \
               'Internal VLAN policy : ascending' in output and \
               400 <= vlan_intf1 <= 500 and 400 <= vlan_intf2 <= 500, \
               "Ascending Internal VLAN range assignment failed"
        info("### Ascending Internal VLAN range assignment passed ###\n\n")

        # Checking after no vlan internal range to ensure defaults
        info('### Checking after no vlan internal range to '
             'ensure defaults ###\n')
        s1.cmdCLI("no vlan internal range")
        intf_cmd = "interface " + third_interface
        s1.cmdCLI(intf_cmd)
        s1.cmdCLI("ip address 10.1.1.3/8")
        s1.cmdCLI("exit")
        ret = s1.cmdCLI("do show vlan internal")
        output = ret.split('\n')
        for line in output:
            if '\t' + third_interface in line:
                vlan_output = line.strip().split('\t')
                vlan_intf3 = int(vlan_output[0])
        assert 'Internal VLAN range  : 1024-4094' in output and \
               'Internal VLAN policy : ascending' in output and \
               1024 <= vlan_intf3 <= 4094, "Default Internal VLAN "\
               "range assignment failed"
        info("### Default Internal VLAN range assignment passed ###\n\n")

        # Checking descending functionality working
        info('### Running the command "vlan internal range 3000 4000 ' \
             'descending" ###\n')
        s1.cmdCLI("vlan internal range 3000 4000 descending")
        intf_cmd = "interface " + fourth_interface
        s1.cmdCLI(intf_cmd)
        s1.cmdCLI("ip address 10.1.1.4/8")
        s1.cmdCLI("exit")
        ret = s1.cmdCLI("do show vlan internal")
        output = ret.split('\n')
        for line in output:
            if '\t' + fourth_interface in line:
                vlan_output = line.strip().split('\t')
                vlan_intf4 = int(vlan_output[0])
        assert 'Internal VLAN range  : 3000-4000' in output and \
               'Internal VLAN policy : descending' in output and \
               3000 <= vlan_intf4 <= 4000, \
               "Descending Internal VLAN range assignment failed"
        info("### Descending Internal VLAN range assignment passed ###\n\n")

        # Checking L2 VLAN assignment
        # Steps: 1. Add an L3 interface to get the internal VLAN 500
        #        2. Try to add an L2 VLAN 500. Should get error
        #        3. Now make the interface L2 using no routing
        #        4. Try to add L2 VLAN 500. Should work
        info('### Checking L2 VLAN and internal VLAN co-existing behavior ###\n')
        s1.cmdCLI("vlan internal range 500 600 ascending")
        intf_cmd = "interface " + fifth_interface
        s1.cmdCLI(intf_cmd)
        s1.cmdCLI("ip address 10.1.1.5/8")
        s1.cmdCLI("exit")
        ret = s1.cmd('/usr/bin/ovs-vsctl add-vlan bridge_normal 500')
        assert 'transaction error' in ret, "L2 VLAN validation failed"
        intf_cmd = "interface " + fifth_interface
        s1.cmdCLI(intf_cmd)
        s1.cmdCLI("no routing")
        s1.cmdCLI("exit")
        s1.cmd('/usr/bin/ovs-vsctl add-vlan bridge_normal 500')
        ret = s1.ovscmd('/usr/bin/ovs-vsctl get VLAN VLAN500 name')
        assert 'VLAN500' in ret, "L2 VLAN validation failed"
        info("### L2 VLAN validation passed ###\n\n")

        # Checking internal VLAN assignment based on L2 VLAN
        # Steps: 1. Add an L2 VLAN 501. L2 VLAN 500 already present
        #        2. Set the internal VLAN range to start at 500
        #        2. Create an L3 interface. Should get internal VLAN 502
        #        3. Now delete L2 VLAN 501.
        #        4. Assign another L3 interface. Should get internal VLAN 501
        info('### Checking internal VLAN assignment based on L2 VLAN ###\n')
        ret = s1.cmd('/usr/bin/ovs-vsctl add-vlan bridge_normal 501')
        intf_cmd = "interface " + sixth_interface
        s1.cmdCLI(intf_cmd)
        s1.cmdCLI("ip address 10.1.1.6/8")
        s1.cmdCLI("exit")
        ret = s1.cmdCLI("do show vlan internal")
        output = ret.split('\n')
        for line in output:
            if '\t' + sixth_interface in line:
                vlan_output = line.strip().split('\t')
                vlan_intf6 = int(vlan_output[0])
        assert 'Internal VLAN range  : 500-600' in output and \
               'Internal VLAN policy : ascending' in output and \
               vlan_intf6 == 502, \
               "Internal VLAN assignment failed"
        s1.cmd('/usr/bin/ovs-vsctl del-vlan bridge_normal 501')
        intf_cmd = "interface " + seventh_interface
        s1.cmdCLI(intf_cmd)
        s1.cmdCLI("ip address 10.1.1.7/8")
        s1.cmdCLI("exit")
        ret = s1.cmdCLI("do show vlan internal")
        output = ret.split('\n')
        for line in output:
            if '\t' + seventh_interface in line:
                vlan_output = line.strip().split('\t')
                vlan_intf7 = int(vlan_output[0])
        assert 'Internal VLAN range  : 500-600' in output and \
               'Internal VLAN policy : ascending' in output and \
               vlan_intf7 == 501, \
               "Internal VLAN assignment failed"
        info("### Internal VLAN assignment passed ###\n\n")

        #Cleanup
        s1.cmdCLI("exit")
        info('########## Internal VLAN functionality works as ' \
             'expected ##########\n\n')

class Test_l3portd_vlan_int:

    def setup_class(cls):
        # Create a test topology
        Test_l3portd_vlan_int.test = vlanInternalCT()

    def teardown_class(cls):
        # Stop the Docker containers, and
        # mininet topology
        Test_l3portd_vlan_int.test.net.stop()

    def test_vlan_internal_cli(self):
        self.test.test_vlan_internal_cli()

    def test_vlan_internal_functionality(self):
        self.test.test_vlan_internal_functionality()

    def __del__(self):
        del self.test
