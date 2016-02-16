# Proxy ARP Feature Test Cases

- [Proxy ARP on a L3 port](#proxy-arp-on-a-l3-port)
- [Proxy ARP on a L2 port](#proxy-arp-on-a-l2-port)
- [proxy ARP on a L3 VLAN interface](#proxy-arp-on-a-l3-vlan-interface)
- [Proxy ARP on a split parent interface](#proxy-arp-on-a-split-parent-interface)
- [Proxy ARP on a split child interface](#proxy-arp-on-a-split-child-interface)
- [Proxy ARP on a sub-interface](#proxy-arp-on-a-sub-interface)
- [Proxy ARP behaviour on a secondary IP address configured interface and on IP modification](#proxy-arp-behaviour-on-a-secondary-ip-address-configured-interface-and-on-ip-modification)
- [Proxy ARP behaviour on interface deletion](#proxy-arp-behaviour-on-interface-deletion)

## Proxy ARP on a L3 port ##

### Objective ###
This test case verifies if proxy ARP can be enabled and disabled on a L3 port.

### Requirements ###
- OpenSwitch FT framework
- **FT file**: ops-portd/tests/test_portd_ft_proxy_arp.py

### Setup ###
#### Topology Diagram ####
```ditaa
+--------+               +--------+                +--------+
|        |             1 |        | 2              |        |
|Switch2 +---------------+Switch1 +----------------+Switch3 |
|        |               |        |                |        |
+--------+               +--------+                +--------+

```

### Description ###
- Configure IPv4 address on Switch2 with subnet mask 16 and Switch1, Switch3 with subnet mask 24. Add a static route on Switch3 to Switch2 through Switch1.
- From Switch2 CLI, execute the `ping <destinationIP>` command where the destination IP is the IPv4 address configured on switch3.
- Verify that the ping has failed and ARP table of Switch2 does not have an entry for Switch3 IP address.
- Enable proxy ARP on L3 port 1 of Switch1 through CLI or REST.
- Verify on Switch1 via CLI display command that proxy ARP is enabled on the L3 port 1.
- Verify on Switch1 via sysctl that proxy ARP is enabled on the L3 port 1 in kernel.
- From Switch2 CLI, execute the `ping <destinationIP>` command where the destination IP is the IPv4 address configured on switch3.
- Verify that the ping is successful and the ARP table of Switch2 has Switch1 MAC corresponding to Switch3 IP address.
- Clear ARP entries of Switch2 by disabling the Switch2 interface. Enable back the interface.
- Disable proxy ARP on L3 port 1 of Switch1 through CLI or REST.
- Verify on Switch1 via CLI display command that proxy ARP is disabled on Port 1.
- Verify on Switch1 via sysctl that proxy ARP is disabled on the L3 port 1 in kernel.
- From Switch2 CLI, execute the `ping <destinationIP>` command where the destination IP is the IPv4 address configured on switch3.
- Verify that the ping has failed and ARP table of Switch2 do not have an entry for the Switch3 IP address.

##  Proxy ARP on a L2 port ##

### Objective ###
This test case verifies that proxy ARP
- will be disabled when routing is disabled.
- cannot be enabled on a L2 port.

### Requirements ###
- OpenSwitch FT framework
- **FT file**: ops-portd/tests/test_portd_ft_proxy_arp.py

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
- Enable proxy ARP on a L3 port through CLI or REST.
- Verify from CLI that proxy ARP is enabled on the L3 port.
- Verify via sysctl that proxy ARP is enabled on the L3 port in kernel.
- Disable routing on the L3 port through CLI or REST.
- Verify from CLI that the proxy ARP is disabled on the port which is now L2.
- Verify via sysctl that proxy ARP is disabled on the L2 port in kernel.
- Try to enable proxy ARP on the L2 port.
- Verify from CLI that proxy ARP cannot be enabled on the L2 port.

## Proxy ARP on a L3 VLAN interface ##

### Objective ###
This test case verifies if proxy ARP can be enabled and disabled on a L3 VLAN interface.

### Requirements ###
- OpenSwitch FT framework
- **FT file**: ops-portd/tests/test_portd_ft_proxy_arp.py

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
- Enable proxy ARP on a L3 VLAN interface through CLI or REST.
- Verify from CLI that proxy ARP is enabled on the L3 VLAN interface.
- Verify via sysctl that proxy ARP is enabled on the L3 VLAN interface in kernel.
- Disable proxy ARP on a L3 VLAN interface through CLI or REST.
- Verify from CLI that the proxy ARP is disabled on the L3 VLAN interface.
- Verify via sysctl that proxy ARP is disabled on the L3 VLAN interface in kernel.


## Proxy ARP on a split parent interface ##

### Objective ###
This test verifies that proxy ARP
- Can be enabled on a parent interface that is not split.
- Cannot be enabled on a parent interface that is already split.

### Requirements ###
- OpenSwitch FT framework
- **FT file**: ops-portd/tests/test_portd_ft_proxy_arp.py

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
- Enable proxy ARP on a non-split parent interface through CLI or REST.
- Verify that proxy ARP is enabled from CLI.
- Verify via sysctl that proxy ARP is enabled on the parent interface in kernel.
- Split the parent interface through CLI or REST.
- Verify from CLI that proxy ARP is disabled on the parent interface that is split.
- Verify via sysctl that proxy ARP is disabled on the parent interface in kernel.
- Try to enable proxy ARP on the split parent interface through CLI or REST.
- Verify from CLI that proxy ARP cannot be enabled on a parent interface that is already split.
- Verify via sysctl that proxy ARP is disabled on the parent interface in kernel.


##  Proxy ARP on a split child interface ##

### Objective ###
This test verifies that proxy ARP
- Cannot be enabled on a child interface of a parent interface that is not split.
- Can be enabled on a child interface of a parent that is split.
- Proxy ARP configuration on a child interface is removed if the parent is reset to no-split.

### Requirements ###
- OpenSwitch FT framework
- **FT file**: ops-portd/tests/test_portd_ft_proxy_arp.py

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

- Enable proxy ARP on a child interface of a non-split parent interface through CLI or REST.
- Verify from CLI that proxy ARP is not enabled.
- Verify via sysctl that proxy ARP is disabled on the child interface in kernel.
- Split the parent interface and enable proxy ARP on the child interface through CLI or REST.
- Verify from CLI that proxy ARP is enabled.
- Verify via sysctl that proxy ARP is enabled on the child interface in kernel.
- Do a **no split** on a parent interface that is split.
- Verify that proxy ARP is disabled on the child interface from CLI.
- Verify via sysctl that proxy ARP is disabled on the child interface in kernel.

##  Proxy ARP on a sub-interface ##

### Objective ###
This test case verifies that proxy ARP cannot be enabled on a sub-interface.

### Requirements ###
- OpenSwitch FT framework
- **FT file**: ops-portd/tests/test_portd_ft_proxy_arp.py

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
- Try to enable proxy ARP on a sub-interface.
- Verify from CLI that proxy ARP cannot be enabled on a sub-interface.

## Proxy ARP behaviour on a secondary IP address configured interface and on IP modification ##

### Objective ###
This test case verifies proxy ARP working on
- an interface which has secondary ip address configured.
- IP modification on the proxy ARP enabled interface.


### Requirements ###
- OpenSwitch FT framework
- **FT file**: ops-portd/tests/test_portd_ft_proxy_arp.py

### Setup ###
#### Topology Diagram ####
```ditaa
+--------+               +--------+                +--------+
|        |             1 |        | 2              |        |
|Switch2 +---------------+Switch1 +----------------+Switch3 |
|        |               |        |                |        |
+--------+               +--------+                +--------+

```

### Description ###
- Configure IPv4 address on Switch2 with subnet mask 16 and Switch1, Switch3 with subnet mask 24. Add a static route on Switch3 to Switch2 through Switch1.
- Configure a secondary IP address on port 1 of Switch1.
- From Switch2 CLI, execute the `ping <destinationIP>` command where the destination IP is the IPv4 address configured on switch3.
- Verify that the ping has failed and ARP table of Switch2 does not have an entry for Switch3 IP address.
- Enable proxy ARP on L3 port 1 of Switch1 through CLI or REST.
- Verify on Switch1 via CLI display command that proxy ARP is enabled on the L3 port 1.
- Verify on Switch1 via sysctl that proxy ARP is enabled on the L3 port 1 in kernel.
- From Switch2 CLI, execute the `ping <destinationIP>` command where the destination IP is the IPv4 address configured on switch3.
- Verify that the ping is successful and the ARP table of Switch2 has Switch1 MAC corresponding to Switch3 IP address.
- Clear ARP entries of Switch2 by disabling the Switch2 interface. Enable back the interface.
- Modify the configured primary IPv4 address on port 1 of Switch1 to a newer IPv4 address which is in the same subnet as the previously configured IPv4 address.
- From Switch2 CLI, execute the `ping <destinationIP>` command where the destination IP is the IPv4 address configured on switch3.
- Verify that the ping is successful and the ARP table of Switch2 has Switch1 MAC corresponding to Switch3 IP address.

## Proxy ARP behaviour on interface deletion ##

### Objective ###
This test case verifies the bahaviour of proxy ARP on deleting an interface on which the proxy ARP is enabled.

### Requirements ###
- OpenSwitch FT framework
- **FT file**: ops-portd/tests/test_portd_ft_proxy_arp.py

### Setup ###
#### Topology Diagram ####
```ditaa
+--------+               +--------+                +--------+
|        |             1 |        | 2              |        |
|Switch2 +---------------+Switch1 +----------------+Switch3 |
|        |               |        |                |        |
+--------+               +--------+                +--------+

```

### Description ###
- Configure IPv4 address on Switch2 with subnet mask 16 and Switch1, Switch3 with subnet mask 24. Add a static route on Switch3 to Switch2 through Switch1.
- From Switch2 CLI, execute the `ping <destinationIP>` command where the destination IP is the IPv4 address configured on switch3.
- Verify that the ping has failed and ARP table of Switch2 does not have an entry for Switch3 IP address.
- Enable proxy ARP on L3 port 1 of Switch1 through CLI or REST.
- Verify on Switch1 via CLI display command that proxy ARP is enabled on the L3 port 1.
- Verify on Switch1 via sysctl that proxy ARP is enabled on the L3 port 1 in kernel.
- From Switch2 CLI, execute the `ping <destinationIP>` command where the destination IP is the IPv4 address configured on switch3.
- Verify that the ping is successful and the ARP table of Switch2 has Switch1 MAC corresponding to Switch3 IP address.
- Clear ARP entries of Switch2 by disabling the Switch2 interface. Enable back the interface.
- Delete the interface 1 of Switch1 through CLI or REST.
- Verify on Switch1 via CLI display command that the interface 1 is deleted.
- Verify on Switch1 via sysctl that proxy ARP is disabled on the port 1 in kernel.
- From Switch2 CLI, execute the `ping <destinationIP>` command where the destination IP is the IPv4 address configured on switch3.
- Verify that the ping has failed and ARP table of Switch2 do not have an entry for the Switch3 IP address.
