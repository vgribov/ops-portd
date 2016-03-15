
# Portd Test Cases

## Contents

- [Create vlan interface](#create-vlan-interface)
- [Add IPv4 address](#add-ipv4-address)
- [Delete IPv4 address](#delete-ipv4-address)
- [Add IPv6 address](#add-ipv6-address)
- [Delete IPv6 address](#delete-ipv6-address)
- [Delete vlan interface](#delete-vlan-interface)
- [Validate Linux bonding driver configuration when LAG is configured](#validate-linux-bonding-driver-configuration-when-lag-is-configured)
- [Validate L2 LAG bonding interface behavior related to bridge_normal](#validate-l2-lag-bonding-interface-behavior-related-to-bridge_normal)

##  Create vlan interface
### Objective
Test case checks creation of vlan interface.
### Requirements
- Virtual Mininet Test Setup
- **CT File**: ops-portd/test/test_portd_ct_inter_vlan_interface.py

### Setup
Single Switch Topology

### Description
Run commands:
```
(config)# interface vlan 10
(config-if)#
$ /sbin/ip netns exec swns bash
$ ifconfig -a vlan10
```
### Test Result Criteria
#### Test Pass Criteria
The new vlan interface (vlan10) should be created on top of `bridge_normal` interface and in `UP` state.
#### Test Fail Criteria

##  Add IPv4 address
### Objective
Test addition of IPv4 address
### Requirements
- Virtual Mininet Test Setup
- **CT File**: ops-portd/test/test_portd_ct_inter_vlan_interface.py

### Setup
Single Switch Topology

### Description
Run commands:
```
(config)# interface vlan 10
(config-if)#  ip address 192.168.0.1/24
(config-if)#
$ /sbin/ip netns exec swns bash
$ ip addr show vlan10
```
### Test Result Criteria
#### Test Pass Criteria
IPv4 address should be assigned to vlan10 interface.
#### Test Fail Criteria

##  Delete IPv4 address
### Objective
Test deletion of IPv4 address
### Requirements
- Virtual Mininet Test Setup
- **CT File**: ops-portd/test/test_portd_ct_inter_vlan_interface.py

### Setup
Single Switch Topology

### Description
Run commands:
```
(config)# interface vlan 10
(config-if)#  no ip address 192.168.0.1/24
(config-if)#
$ /sbin/ip netns exec swns bash
$ ip addr show vlan10
```
### Test Result Criteria
#### Test Pass Criteria
Interface should not have any IPv4 address.
#### Test Fail Criteria

##  Add IPv6 address
### Objective
Test addition of IPv6 address
### Requirements
- Virtual Mininet Test Setup
- **CT File**: ops-portd/test/test_portd_ct_inter_vlan_interface.py

### Setup
Single Switch Topology

### Description
Run commands:
```
(config)# interface vlan 10
(config-if)#  ipv6 address 2000::1/120
(config-if)#
$ /sbin/ip netns exec swns bash
$ ip addr show vlan10
```
### Test Result Criteria
#### Test Pass Criteria
IPv6 address should be assigned to vlan10 interface.
#### Test Fail Criteria

##  Delete IPv6 address
### Objective
Test deletion of IPv6 address
### Requirements
- Virtual Mininet Test Setup
- **CT File**: ops-portd/test/test_portd_ct_inter_vlan_interface.py

### Setup
Single Switch Topology

### Description
Run commands:
```
(config)# interface vlan 10
(config-if)#  no ipv6 address 2000::1/120
(config-if)#
$ /sbin/ip netns exec swns bash
$ ip addr show vlan10
```
### Test Result Criteria
#### Test Pass Criteria
Interface should not have any IPv6 address.
#### Test Fail Criteria

##  Delete vlan interface
### Objective
Test case checks for deletion of vlan interface
### Requirements
- Virtual Mininet Test Setup
- **CT File**: ops-portd/test/test_portd_ct_inter_vlan_interface.py

### Setup
Single Switch Topology

### Description
Run commands:
```
(config)# no interface vlan 10
$ /sbin/ip netns exec swns bash
$ ifconfig -a
```
### Test Result Criteria
#### Test Pass Criteria
vlan interface (vlan10) created earlier should no longer exist.
#### Test Fail Criteria

## Validate Linux bonding driver configuration when LAG is configured
### Objective
Verify that Linux bonding driver is properly configured when LAGs are created
and deleted, also when interfaces are added and removed.
### Requirements
- Virtual Mininet Test Setup
- **CT File**: ops-portd/test/test_portd_ct_linux_bonding_driver_configuration.py

### Setup
#### Topology diagram
```ditaa

   +-----+------+
   |            |
   |  Switch 1  |
   |            |
   +-+---+---+--+
     |   |   |
     |   |   |      LAG 1
     |   |   |
   +-+---+---+--+
   |            |
   |  Switch 2  |
   |            |
   +-----+------+

```

### Description
This test verifies Linux bonding drivers files are configured correctly when
LAG is created/deleted and when interfaces are added/removed.

  1. Create LAG in both switches with interfaces 1 and 2.
  2. Execute "ifconfig" and check if Linux bond interface exists.
  3. Add interface 3 to the LAG in both switches.
  4. Check the slaves associated to the Linux bond in the file:
     /sys/class/net/<lag_name>/bonding/slaves.
  5. Remove interface 1 from LAG in switch 1.
  6. Remove interface 2 from LAG in switch 2.
  7. Check the slaves associated to the Linux bond in the file:
     /sys/class/net/<lag_name>/bonding/slaves.
  8. Delete LAG in both switches.
  9. Execute "ifconfig" and check if Linux bond interface exists.


### Test Result Criteria
#### Test Pass Criteria
 1. A Linux bond interface specific for the LAG is created when the LAG is
    configured and is deleted when the LAG is removed.
 2. The interfaces added to a LAG are also associated as slaves of the Linux
    bond of that LAG.
 3. The interfaces removed from a LAG are also removed from the list of
    slaves of the Linux bond for that LAG.
#### Test Fail Criteria
 1. A Linux bond interface specific for the LAG is not created when the LAG is
    configured or is not deleted when the LAG is removed.
 2. The interfaces added to a LAG are not associated as slaves of the Linux
    bond of that LAG.
 3. The interfaces removed from a LAG are not removed from the list of
    slaves of the Linux bond for that LAG.


## Validate L2 LAG bonding interface behavior related to bridge_normal
### Objective
Verify Linux bonding interface for L2 LAG is properly added or remove from
the bridge_normal. Also verify if L2 interfaces added to the LAG are removed
from bridge_normal.
### Requirements
- Modular Framework or OSTL
- **FT File**: ops-portd/ops-tests/feature/test_portd_ft_l2_lag_bridge_normal.py

### Setup
#### Topology diagram
```ditaa

   +-----+------+
   |            |
   |  Switch 1  |
   |            |
   +---+----+---+
       |    |
       |    | LAG 1
       |    |
   +---+----+---+
   |            |
   |  Switch 2  |
   |            |
   +-----+------+

```

### Description
This test verifies the ports in bridge_normal are properly updated
according to the configuration of L2 LAGs and ports.

  1. Turn on interfaces 1 and 2 in both switches.
  2. Set interface 1 and 2 as no routing in both switches.
  3. Check the ports of bridge_normal.
  4. Create LAG in both switches with interfaces 1 and 2.
  5. Check the ports of bridge_normal.
  6. Configure the LAG as a L3 LAG in both switches.
  7. Check the ports of bridge_normal.
  8. Configure the LAG as a L2 LAG in both switches.
  9. Check the ports of bridge_normal.
  10. Delete LAG in both switches.
  11. Check the ports of bridge_normal.


### Test Result Criteria
#### Test Pass Criteria
 1. The bond port specific for the LAG is added to bridge_normal when
    it is configured as L2 LAG.
 2. The L2 ports added to a LAG are removed from bridge_normal.
 3. The bond port specific for a LAG is removed from bridge_normal when
    the LAG is configured as L3 or is deleted.
#### Test Fail Criteria
 1. The bond port specific for the LAG is not added to bridge_normal when
    it is configured as L2 LAG.
 2. The L2 ports added to a LAG are not removed from bridge_normal.
 3. The bond port specific for a LAG is not removed from bridge_normal
    when the LAG is configured as L3 or is deleted.
