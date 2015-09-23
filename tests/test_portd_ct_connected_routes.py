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

class connectedRoutesCTTest( OpsVsiTest ):

    def setupNet(self):
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        portd_topo = SingleSwitchTopo(k=0, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(portd_topo, switch=VsiOpenSwitch,
                           host=Host, link=OpsVsiLink,
                           controller=None, build=True)

    def testConfigure(self):
        info('\n########## Test portd addition of connected routes ##########\n')
        info('\n### Configuring the topology ###\n')
        s1 = self.net.switches[ 0 ]

        s1.ovscmd("/usr/bin/ovs-vsctl set interface 1 user_config:admin=up")
        s1.ovscmd("/usr/bin/ovs-vsctl set interface 2 user_config:admin=up")

        # Configure switch s1
        s1.cmdCLI("configure terminal")

        # Configure interface 1 on switch s1
        s1.cmdCLI("interface 1")
        s1.cmdCLI("ip address 10.0.10.1/24")
        s1.cmdCLI("ipv6 address 2000::1/120")
        s1.cmdCLI("exit")

        # Configure interface 2 on switch s1
        s1.cmdCLI("interface 2")
        s1.cmdCLI("ip address 10.0.20.1/24")
        s1.cmdCLI("ipv6 address 2001::1/120")
        s1.cmdCLI("exit")

        info('### Switch s1 configured ###\n')

        info('### Configuration on s1 complete ###\n')

    def testConnectedRoutes(self):
        info('\n\n### Verify connected routes are present in db ###\n')
        s1 = self.net.switches[ 0 ]

        # Parse the "ovsdb-client dump" output and extract the lines between
        # "Route table" and "Route_Map table". This section will have all the
        # Route table entries. Then parse line by line to match the contents
        dump = s1.cmd("ovsdb-client dump")
        lines = dump.split('\n')
        check = False
        count = 0
        for line in lines:
            if check:
                if ('connected' in line and 'unicast' in line and
                '10.0.10.0/24' in line and 'true' in line):
                    #print '\nIPv4 connected route found. Success!\n'
                    #print line
                    count = count + 1
                    #print '\n'
                elif ('connected' in line and 'unicast' in line and
                '10.0.20.0/24' in line and 'true' in line):
                    #print '\nIPv4 connected route found. Success!\n'
                    #print line
                    count = count + 1
                    #print '\n'
                elif ('connected' in line and 'unicast' in line and
                '2000::/120' in line and 'true' in line):
                    #print '\nIPv6 connected route found. Success!\n'
                    #print line
                    count = count + 1
                    #print '\n'
                elif ('connected' in line and 'unicast' in line and
                '2001::/120' in line and 'true' in line):
                    #print '\nIPv6 connected route found. Success!\n'
                    #print line
                    count = count + 1
                    #print '\n'
            if 'Route table' in line:
                check = True
            if 'Route_Map table' in line:
                check = False
        assert count == 4, "Connected routes not populated in DB"

        info('########## Test Passed ##########\n\n\n')

class Test_portd_connected_routes:

    def setup_class(cls):
        Test_portd_connected_routes.test = connectedRoutesCTTest()

    def teardown_class(cls):
        # Stop the Docker containers, and
        # mininet topology
        Test_portd_connected_routes.test.net.stop()

    def test_testConfigure(self):
        # Function to configure the topology
        self.test.testConfigure()

    def test_testZebra(self):
        # Function to validate connected routes in db
        self.test.testConnectedRoutes()
        #CLI(self.test.net)

    def __del__(self):
        del self.test
