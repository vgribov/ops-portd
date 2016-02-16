# Proxy ARP Component Test Cases

- [Proxy ARP on a L3 port](#proxy-arp-on-a-l3-port)
- [Proxy ARP on a L2 port](#proxy-arp-on-a-l2-port)
- [Proxy ARP on a L3 VLAN interface](#proxy-arp-on-a-l3-vlan-interface)
- [Proxy ARP on a split parent interface](#proxy-arp-on-a-split-parent-interface)
- [Proxy ARP on a split child interface](#proxy-arp-on-a-split-child-interface)
- [Proxy ARP behaviour on interface deletion](#proxy-arp-behaviour-on-interface-deletion)

## Proxy ARP on a L3 port ##

### Objective ###
This test case verifies if the proxy arp can be enabled and disabled on a L3 port.

### Requirements ###
- Mininet test setup
- **CT file**: ops-portd/tests/test_portd_ct_proxy_arp.py

### Setup ###
#### Topology Diagram ####
```ditaa
              +------------------+
              |                  |
              |     Switch       |
              |                  |
              +------------------+
```

### Description ###
- Modify the OVSDB contents of column **other_config** with key **proxy_arp_enabled** in row of **port** table corresponding to L3 port to **true** to enable proxy ARP on the L3 port.
- Verify via sysctl that proxy ARP is enabled on the interface in kernel.
- Modify the OVSDB contents of column **other_config** and remove the key **proxy_arp_enabled** in row of **port** table corresponding to L3 port to disable proxy ARP on the L3 port.
- Verify via sysctl that proxy ARP is disabled on the interface in kernel.

##  Proxy ARP on a L2 port ##

### Objective ###
This test case verifies that the proxy ARP cannot be enabled on a L2 port.

### Requirements ###
- Mininet test setup
- **CT file**: ops-portd/tests/test_portd_ct_proxy_arp.py

### Setup ###
#### Topology Diagram ####
```ditaa
              +------------------+
              |                  |
              |     switch       |
              |                  |
              +------------------+
```

### Description ###
- Configure a L2 port by adding port to a bridge.
- Try to enable proxy ARP on L2 port by modifying the OVSDB contents of column **other_config** with key **proxy_arp_enabled** in row of **port** table corresponding to L2 port to **true**.
- Verify via sysctl that proxy ARP is not enabled on the interface in kernel.

## Proxy ARP on a L3 VLAN interface ##

### Objective ###
This test case verifies if the proxy arp can be enabled and disabled on a L3 VLAN interface.

### Requirements ###
- Mininet test setup
- **CT file**: ops-portd/tests/test_portd_ct_proxy_arp.py

### Setup ###
#### Topology Diagram ####
```ditaa
              +------------------+
              |                  |
              |     Switch       |
              |                  |
              +------------------+
```

### Description ###
-  Modify the OVSDB contents of column **other_config** with key **proxy_arp_enabled** in row of  **port** table corresponding to **vlan interface** to **true** to enable proxy ARP on the L3 VLAN interface.
-  Verify via sysctl that proxy ARP is enabled on the L3 VLAN interface in kernel.
-  Modify the OVSDB contents of column **other_config** and remove the key **proxy_arp_enabled** in row of **port** table corresponding to **vlan interface** to disable proxy ARP on the L3 VLAN interface.
-  Verify via sysctl that proxy ARP is disabled on the L3 VLAN interface in kernel.


## Proxy ARP on a split parent interface ##

### Objective ###
This test verifies that proxy ARP
- Can be enabled on a parent interface that is not split.
- Cannot be enabled on a parent interface that is already split.

### Requirements ###
- Mininet test setup
- **CT file**: ops-portd/tests/test_portd_ct_proxy_arp.py

### Setup ###
#### Topology Diagram ####
```ditaa
              +------------------+
              |                  |
              |     switch       |
              |                  |
              +------------------+
```

### Description ###
- Modify the OVSDB contents of column **other_config** with key **proxy_arp_enabled** in row of **port** table corresponding to **split interface** to **true** to enable proxy ARP.
- Verify via sysctl that proxy ARP is enabled on the parent interface in kernel.
- Split the parent interface by modifying the OVSDB contents of column **user_config** with key **lane_split** in row of **Interface** table corresponding to split interface to **split** and by removing the port reference from VRF.
- Verify that the port table does not have the row for the interface.
- Verify via sysctl that proxy ARP is disabled on the parent interface in kernel.


##  Proxy ARP on a split child interface ##

### Objective ###
This test verifies that proxy ARP
- Cannot be enabled on a child interface of a parent interface that is not split.
- Can be enabled on a child interface of a parent that is split.
- Removes proxy ARP configuration on a child interface if the parent is reset to no split.

### Requirements ###
- Mininet test setup
- **CT file**: ops-portd/tests/test_portd_ct_proxy_arp.py

### Setup ###
#### Topology Diagram ####
```ditaa
              +------------------+
              |                  |
              |     switch       |
              |                  |
              +------------------+
```

### Description ###

- Split the parent interface by modifying the OVSDB contents of column **user_config** with key **lane_split** in row of **Interface** table corresponding to split interface to **split** and by removing the port reference from VRF.
- Verify that the port table does not have the row for the parent interface.
- Modify the OVSDB contents of column **other_config** with key **proxy_arp_enabled** in row of **port** table corresponding to **split child interface** to **true** to enable proxy ARP.
- Verify via sysctl that proxy ARP is enabled on the child interface in kernel.
- Configure the parent as **no split** by clearing the OVSDB contents of column **user_config** in row of **Interface** table corresponding to the split interfaace and by removing the child port references from VRF.
- Verify that the port table now has a row for the parent interface.
- Verify via sysctl that proxy ARP is disabled on the parent interface in kernel.

## Proxy ARP behaviour on interface deletion ##

### Objective ###
This test case verifies the bahaviour of proxy ARP on deleting an interface on which the proxy ARP is enabled.

### Requirements ###
- Mininet test setup
- **CT file**: ops-portd/tests/test_portd_ft_proxy_arp.py

### Setup ###
#### Topology Diagram ####
```ditaa
              +------------------+
              |                  |
              |     Switch       |
              |                  |
              +------------------+
```

### Description ###
- Modify the OVSDB contents of column **other_config** with key **proxy_arp_enabled** in **port** table corresponding to L3 port to **true** to enable proxy ARP on the L3 port.
- Verify via sysctl that proxy ARP is enabled on the interface in kernel.
- Delete the interface on which the proxy ARP is enabled by removing the port reference from VRF.
- Verify via sysctl that proxy ARP is disabled on the interface in kernel.
