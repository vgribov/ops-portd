ops-portd
=========

What is ops-portd?
------------------
The ops-portd storage area is the repository for the OpenSwitch ops-portd daemon.

The ops-portd daemon

* Updates the Linux kernel with the L3 interface IPv4 and IPv6 addresses.
* Controls the L3 interface admin status (up or down) and manages the internal VLAN allocation for the L3 interfaces.
* Updates the database with routes for directly connected subnets.
* Manages the logical VLAN interfaces for interVLAN routing.

What is the structure of the repository?
----------------------------------------
* src - contains all source files.
* include - contains all .h files.
* files - contains files required for ops-portd.
* tests - contains all automated tests for ops-portd.

What is the license?
--------------------
Apache 2.0 license. For more details refer to [COPYING](https://git.openswitch.net/cgit/openswitch/ops-portd/tree/COPYING)

What other documents are available?
-----------------------------------
For the high level design of ops-portd daemon, refer to [DESIGN](https://git.openswitch.net/cgit/openswitch/ops-portd/tree/DESIGN.md)

For the current list of contributors and maintainers, refer to [AUTHORS](https://git.openswitch.net/cgit/openswitch/ops-portd/tree/AUTHORS)

For general information about OpenSwitch project refer to http://www.openswitch.net
