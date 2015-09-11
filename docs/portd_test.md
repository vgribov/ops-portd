
# Portd Test Cases

## Contents

- [Create vlan interface](#create-vlan-interface)
- [Add IPv4 address](#add-ipv4-address)
- [Delete IPv4 address](#delete-ipv4-address)
- [Add IPv6 address](#add-ipv6-address)
- [Delete IPv6 address](#delete-ipv6-address)
- [Delete vlan interface](#delete-vlan-interface)

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
