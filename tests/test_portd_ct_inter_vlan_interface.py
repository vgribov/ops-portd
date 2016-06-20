#!/usr/bin/python

# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
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

vlan_interface = "vlan10"
PORTD_INIT_SLEEP_TIME = 15
PORTD_TEST_SLEEP_TIME = 5


class Inter_VLAN_Interface_CT(OpsVsiTest):

    def setupNet(self):
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        portd_topo = SingleSwitchTopo(k=0, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(portd_topo, switch=VsiOpenSwitch,
                           host=Host, link=OpsVsiLink,
                           controller=None, build=True)

    def test_intervlan_interface(self):
        '''
            Create/Delete inter-VLAN interface in kernel, when configured in
            Openswitch.
        '''
        s1 = self.net.switches[0]

        s1.cmdCLI("configure terminal")
        s1.cmdCLI("vlan 10")
        s1.cmdCLI("no shutdown")

        info('### CHECK: inter-VLAN interface creation. ###\n')
        s1.cmdCLI("interface " + vlan_interface)
        s1.cmd("ip netns exec swns bash")
        time.sleep(PORTD_TEST_SLEEP_TIME)
        ret = s1.cmd("ifconfig -a " + vlan_interface)
        assert 'vlan10' in ret, \
            'FAIL: inter-VLAN interface creation failed.'
        info('### PASS: inter-VLAN interface creation test passed. ###\n\n')

        info('### CHECK: IPv4 address add to inter-VLAN interface. ###\n\n')
        s1.cmdCLI("ip address 192.168.0.1/30")
        time.sleep(PORTD_TEST_SLEEP_TIME)
        ret = s1.cmd("ip addr show " + vlan_interface)
        assert '192.168.0.1' in ret, \
            'FAIL: test to add IPv4 address to inter-VLAN interface failed.'
        info('### PASS: IPv4 address add to inter-VLAN interface. ###\n\n')

        info('### CHECK: IPv4 address delete from '
             'inter-VLAN interface. ###\n\n')
        s1.cmdCLI("no ip address 192.168.0.1/30")
        time.sleep(PORTD_TEST_SLEEP_TIME)
        ret = s1.cmd("ip addr show " + vlan_interface)
        assert '192.168.0.1' not in ret, \
            'FAIL: test to add IPv4 address to inter-VLAN interface failed.'
        info('### PASS: IPv4 address delete to inter-VLAN interface. ###\n\n')

        info('### CHECK: IPv6 address add to inter-VLAN interface. ###\n\n')
        s1.cmdCLI("ipv6 address 2000::1/120")
        time.sleep(PORTD_TEST_SLEEP_TIME)
        ret = s1.cmd("ip addr show  " + vlan_interface)
        assert '2000::1' in ret, \
            'FAIL: test to add IPv6 address to inter-VLAN interface failed.'
        info('### PASS: IPv6 address add to inter-VLAN interface. ###\n\n')

        info('### CHECK: IPv6 address delete to '
             'inter-VLAN interface. ###\n\n')
        s1.cmdCLI("no ipv6 address 2000::1/120")
        time.sleep(PORTD_TEST_SLEEP_TIME)
        ret = s1.cmd("ip addr show  " + vlan_interface)
        assert '2000::1' not in ret, \
            'FAIL: test to add IPv6 address to inter-VLAN interface failed.'
        info('### PASS: IPv6 address delete to inter-VLAN interface. ###\n\n')

        info('### CHECK: inter-VLAN interface deletion. ###\n')
        # Checking inter-VLAN interface deletion in CLI
        s1.cmdCLI("exit")
        s1.cmdCLI("no interface " + vlan_interface)
        s1.cmd("ip netns exec swns bash")
        time.sleep(PORTD_TEST_SLEEP_TIME)
        ret = s1.cmd("ifconfig -a " + vlan_interface)
        assert 'does not exist' in ret, \
            'FAIL: inter-VLAN interface deletion test failed.'
        info('### Inter-VLAN interface deletion test passed. ###\n\n')

        # Cleanup
        s1.cmdCLI("exit")
        info('########## Inter-VLAN interface CLI validations '
             'passed. ##########\n\n')


@pytest.mark.skipif(True, reason="Disabling old tests")
class Test_portd_intervlan_interface:

    def setup_class(cls):
        # Create a test topology
        Test_portd_intervlan_interface.test = Inter_VLAN_Interface_CT()

    def teardown_class(cls):
        # Stop the Docker containers, and
        # mininet topology
        Test_portd_intervlan_interface.test.net.stop()

    def test_intervlan_interface(self):
        time.sleep(PORTD_INIT_SLEEP_TIME)
        self.test.test_intervlan_interface()

    def __del__(self):
        del self.test
