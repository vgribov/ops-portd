/*
 * Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
 * All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 *
 * File: portd.h
 */

#ifndef PORTD_H_
#define PORTD_H_

#include "hmap.h"
#include "shash.h"
#include "vswitch-idl.h"
#include "openhalon-idl.h"

#define PORTD_DISABLE_ROUTING 0
#define PORTD_ENABLE_ROUTING 1
#define PORTD_POLL_INTERVAL 5
#define PORTD_IPV4_MAX_LEN 32
#define PORTD_IPV6_MAX_LEN 128
#define PORT_INTERFACE_ADMIN_UP "up" // Interface admin state "up"
#define PORT_INTERFACE_ADMIN_DOWN "down" // Interface admin state "down"
#define LOOPBACK_INTERFACE_NAME "lo"
#define RECV_BUFFER_SIZE 4096
/* ifa_scope value of link local IPv6 address */
#define IPV6_ADDR_SCOPE_LINK 253

#define PORTD_EMPTY_STRING ""

#define INET_ADDRSTRLEN     16
#define INET_PREFIX_SIZE    18

#define INET6_ADDRSTRLEN    46
#define INET6_PREFIX_SIZE   49

#define CONNECTED_ROUTE_DISTANCE    0

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

struct port {
    struct hmap_node port_node; /* Element in struct vrf's "ports" hmap. */
    char *name;
    char *type;    /* "internal" for VLAN interfaces/ports and NULL otherwise */
    const struct ovsrec_port *cfg;

    int internal_vid;
    char *ip4_address;
    char *ip6_address;
    struct hmap secondary_ip4addr; /* List of secondary IP address*/
    struct hmap secondary_ip6addr; /*List of secondary IPv6 address*/
    struct vrf *vrf;
};

struct vrf {
    struct hmap_node node;      /* In 'all_vrfs'. */
    char *name;                 /* User-specified arbitrary name. */
    const struct ovsrec_vrf *cfg;

    /* VRF ports. */
    struct hmap ports;          /* "struct port"s indexed by name. */
    /* Used during reconfiguration. */
    struct shash wanted_ports;
};

struct net_address {
    struct hmap_node addr_node;
    char *address;
};

/* IPv4 prefix structure. */
struct prefix_ipv4
{
  u_char family;
  u_char prefixlen;
  struct in_addr prefix __attribute__ ((aligned (8)));
};

/* IPv6 prefix structure. */
struct prefix_ipv6
{
  u_char family;
  u_char prefixlen;
  struct in6_addr prefix __attribute__ ((aligned (8)));
};

struct kernel_port {
    char *name;
    struct hmap ip4addr; /* List of IPv4 address*/
    struct hmap ip6addr; /*List of IPv6 address*/
};

void portd_config_iprouting(int enable);
void portd_reconfig_ipaddr(struct port *port, struct ovsrec_port *port_row);
void portd_del_ipv4_addr(struct port *port);
void portd_del_ipv6_addr(struct port *port);
void portd_del_ipaddr(struct port *port);
void portd_add_ipv4_addr(struct port *port);
void portd_add_ipv6_addr(struct port *port);
void portd_add_ipaddr(struct port *port);
void portd_ipaddr_config_on_init(void);

/* Inter-VLAN functions */
void portd_add_vlan_interface(const char *parent_intf_name,
                                const char *vlan_intf_name,
                                const unsigned short vlan_tag);
void portd_del_vlan_interface(const char *vlan_intf_name);

/* Netlink functions */
void nl_msg_process(void *use_data);
void parse_nl_ip_address_msg(struct nlmsghdr *nlh, int msglen,
                             struct shash *kernel_port_list);

#endif /* PORTD_H_ */
