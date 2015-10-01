# High-level design of ops-portd
The `ops-portd daemon` manages configuration for L3 interfaces to include managing IP addresses, internal VLAN allocation, logical interfaces for inter-VLAN routing, VRF management, connected routes and Linux kernel and database updates.

## Reponsibilities
* Manages VRF additions or deletions by enabling or disabling Linux routing on the VRF.
* Configures the Linux kernel with the L3 interface primary and secondary IPv4 or primary and secondary IPv6 addreses.
* Updates the Linux kernel with the interface admin status (up/down).
* Manages internal VLAN allocation by reserving a VLAN from a configurable range to be used by the system for configuring the L3 interface in the hardware.
* Configures the logical VLAN interface in the Linux kernel for inter-VLAN routing.
* Updates the database with directly connected subnet routes to keep those routes in up-to-date with the Linux kernel.

##  Design choices
The ops-portd was added to OpenSwitch architecture so that there would be one entity responsible for managing the various L3 related configuration items.

## Relationships to external OpenSwitch entities

```ditaa
    +-------------------+   
    |                   |   
    |      OVSDB        |   
    |                   |   
    +--------^----------+   
             |              
             |              
    +--------v----------+   
    |                   |   
    |     ops-portd     |   
    |                   |   
    +--------^----------+   
             |              
             |              
    +--------v----------+   
    |                   |   
    |   Linux kernel    |   
    |                   |   
    +-------------------+   
```

The ops-portd daemon:

* Monitors the VRF table in the database to turn on or off the Linux kernel routing flags.
* Monitors the port table in the database and configures the IP addresses in Linux kernel using netlink sockets.
* Reads the interface table in the database and updates the Linux kernel interface admin flags using netlink sockets.
* Observes the port table for L3 port creation and creates a VLAN entry in the VLAN table and marks it as reserved for internal use.
* Monitors the interface table to detect and internal interface created for inter-VLAN routing and creates a logical VLAN interface in the Linux kernel using netlink sockets.
* Creates and directly connected route entry in the database when an L3 port is configured with an IP address.

## OVSDB-Schema
The ops-portd reads the following columns from subsystem table.
```
  other_info:l3_port_requires_internal_vlan - Determines if system needs to allocate an internal VLAN for the L3 port.
```

The ops-portd reads the following columns from system table:
```
  cur_cfg - To know system is check system is configured at startup.
  other_config:min_internal_vlan - Minimum vlan id for the internal VLAN range.
  other_config:max_internal_vlan - Maximum vlan id for the internal VLAN range.
  other_config:internal_vlan_policy - Internal VLAN allocation policy (ascending/descending)
```

The ops-portd reads the following columns from vrf table:
```
  name - Name of the VRF.
  ports - Ports that are part of this VRF.
```

The ops-portd reads the following columns from bridge table:
```
  name - Name of the bridge.
  vlans - VLANs that are part of this bridge.
  ports - Ports that are part of this bridge.
```
The ops-portd writes the following columns to the bridge table:
```
  vlans - Write the VLAN id for the internal VLAN created for L3 port.
```

The ops-portd reads the following columns from port table:
```
  name - Name of the port.
  ip4_address - Primary IPv4 address of the L3 port.
  ip4_address_secondary - Secondary IPv4 addresses of the L3 port.
  ip6_address - Primary IPv6 address of the L3 port.
  ip6_address_secondary - Secondary IPv6 addresses of the L3 port.
  interfaces - Physical interfaces that are used by this port.
  tag - VLAN tag for this port.
```
The ops-portd writes the following columns to the port table:
```
  hw_config:internal_vlan_id - Internal VLAN id that was allocated for this L3 port.
```

The ops-portd reads the following columns from interface table:
```
  name - Name of the physical interface.
  admin_state - Admin up/down state
  user_config:admin - up/down config status.
  type - Interface type
```

The ops-portd writes the following columns to the vlan table:
```
  name - Name of the VLAN
  id - VLAN id
  admin - Admin state
  oper_state - Operational state
  oper_state_reason - Reason for the operation state
  internal_usage - Internal usage reason. Example, L3.
```

The ops-portd writes the following columns to the route table:
```
  prefix - Directly connected route prefix.
  from - Updates as 'connected' for directly connected route.
  nexthops - nexthop ports for this directly connected route.
  address_family - IPv4/IPv6.
  sub_address_family - 'unicast' for directly connected route.
  distance - 1 for directly connected route.
  selected - true for directly connected route.
  vrf - VRF to which this route belongs.
```

The ops-portd writes the following columns to the nexthop table:
```
  ports - Ports that are the nexthop for the directly connected routes.
```

## Code Design
Initialization : Subscribe to the database tables and columns and initialize the netlink socket.
In case the daemon restarts:

* Ensure that the unused internal VLANs are deleted.
* Ensure that the kernel IP addresses are in sync with the database.
* Ensure that the kernel interface link states are in sync with the database.
* Ensure that the kernel logical VLAN interfaces are in sync with the database.

The ops-portd daemon main loop monitors the:

* VRF additions or deletions to enable or disable Linux routing.
* L3 port creation or deletion under a VRF and create or delete internal VLANs for this L3 port.
* IP address configuration on L3 ports and synchronize the IP addresses with the Linux kernel. Also update the database with the directly connected route entries for the configured IP addresses.
* Interface entry for the type internal and update the corresponding logical VLAN interface in the Linux kernel.
* Netlink socket for new interface creation and update the newly created interface with the database admin status.


## References
* [rtnetlink](http://man7.org/linux/man-pages/man7/rtnetlink.7.html)
