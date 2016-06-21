/*
 * Copyright (C) 2015-2016 Hewlett-Packard Development Company, L.P.
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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "hmap.h"
#include "shash.h"
#include "vswitch-idl.h"
#include "openswitch-idl.h"
#include "vrf-utils.h"
#include "nl-utils.h"
#include "ops-utils.h"

#define PORTD_DISABLE_ROUTING 0
#define PORTD_ENABLE_ROUTING 1
#define PORTD_DISABLE_PROXY_ARP 0
#define PORTD_ENABLE_PROXY_ARP 1
#define PORTD_DISABLE_LOCAL_PROXY_ARP 0
#define PORTD_ENABLE_LOCAL_PROXY_ARP 1
#define PORTD_POLL_INTERVAL 5
#define PORTD_IPV4_MAX_LEN 32
#define PORTD_IPV6_MAX_LEN 128
#define PORTD_VLAN_ID_STRING_MAX_LEN 16
#define PORT_INTERFACE_ADMIN_UP "up" /* Interface admin state "up" */
#define PORT_INTERFACE_ADMIN_DOWN "down" /* Interface admin state "down" */
#define LOOPBACK_INTERFACE_NAME "lo"
#define RECV_BUFFER_SIZE 4096
/* ifa_scope value of link local IPv6 address */
#define IPV6_ADDR_SCOPE_LINK 253

#define PORTD_EMPTY_STRING ""
#define INTERFACE_TYPE_VLAN "vlan"

#define INET_ADDRSTRLEN     16
#define INET_PREFIX_SIZE    18

#define INET6_ADDRSTRLEN    46
#define INET6_PREFIX_SIZE   49
#define PROC_FILE_LENGTH    128

#define CONNECTED_ROUTE_DISTANCE    0

#define PORT_NAME_MAX_LEN 32


#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + \
        NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define VTYSH_STR_EQ(s1, s2) \
        ((strlen((s1)) == strlen((s2))) && \
        (!strncmp((s1), (s2), strlen((s2)))))

#define NL_SOCK(vrf) \
        vrf == NULL?nl_sock: vrf->nl_sock

#define BRIDGE_INT_MAX_RETRY 5

#define SAFE_FREE(x) \
        if (x) {free(x);x = NULL;};

/* Port configuration */
struct port {
    struct hmap_node port_node; /* Element in struct vrf's "ports" hmap. */
    char *name;
    char *type;  /* "internal" for VLAN interfaces/ports and NULL otherwise */
    const struct ovsrec_port *cfg;

    int internal_vid;
    bool hw_cfg_enable;
    bool proxy_arp_enabled;        /* Proxy ARP enabled/disabled */
    bool local_proxy_arp_enabled;  /* Local Proxy ARP enabled/disabled */
    char *ip4_address;             /* Primary IPv4 address */
    char *ip6_address;             /* Primary IPv6 address */
    struct hmap secondary_ip4addr; /* List of secondary IPv4 addresses */
    struct hmap secondary_ip6addr; /* List of secondary IPv6 addresses */
    struct vrf *vrf;
};

/* VRF configuration */
struct vrf {
    struct hmap_node node;      /* In 'all_vrfs'. */
    char *name;                 /* User-specified arbitrary name. */
    const struct ovsrec_vrf *cfg;
    /* VRF ports. */
    struct hmap ports;          /* "struct port"s indexed by name. */
    /* Used during reconfiguration. */
    struct shash wanted_ports;
    int nl_sock;
    int64_t table_id;
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
    struct hmap ip4addr; /* List of IPv4 addresses */
    struct hmap ip6addr; /*List of IPv6 addresses */
};

/* A protocol object part of some forwarding layer object */
struct portd_arbiter_proto_class {
    /* The id associated with the protocol */
    enum ovsrec_port_forwarding_state_proto_e id;

    /* The forwarding layer to which this protocol belongs to */
    struct portd_arbiter_layer_class *layer;

    /* Function that runs and determines if the forwarding state
     * needs to change based on the current protocols state */
    bool (*run) (struct portd_arbiter_proto_class *proto,
                 const struct ovsrec_port *port);

    /* Function that returns the protocols view of the forwarding
     * state of the port. */
    bool (*get_state) (const struct ovsrec_port *port);

    /* Next protocol in the forwarding layer */
    struct portd_arbiter_proto_class *next;
};

/* A forwarding layer object */
struct portd_arbiter_layer_class {
    /* The id associated with the forwarding layer */
    enum ovsrec_port_forwarding_state_layer_e id;

    /* The protocol that is currently determining the state of the forwarding layer */
    enum ovsrec_port_forwarding_state_proto_e owner;

    /* A list of protocols operating at this layer.
     * The order of the list determines precedence among protocols.
     * The protocol at the lower index trumps the one at a higher index. */
    struct portd_arbiter_proto_class *protos;

    /* Boolean variable that tells if the forwarding state of the give layer is blocked */
    bool blocked;

    /* Function that determines if the forwarding state of the layer has to change */
    bool (*run) (struct portd_arbiter_layer_class *layer,
                 const struct ovsrec_port *port);

    /* Pointer to the previous forwarding layer in the hierarchy */
    struct portd_arbiter_layer_class *prev;

    /* Pointer to the next forwarding layer in the hierarchy */
    struct portd_arbiter_layer_class *next;
};

/* A port arbiter object */
struct portd_arbiter_class {
    /* A list of forwarding layers applicable for this object */
    struct portd_arbiter_layer_class *layers;
};

struct ovsrec_port* portd_port_db_lookup(const char *);
/* Helper functions to identify intervlan interfaces */
bool portd_interface_type_internal_check(const struct ovsrec_port *port,
                                         const char *interface_name);
bool portd_port_in_bridge_check(const char *port_name,
                                const char *bridge_name);
bool portd_port_in_vrf_check(const char *port_name, const char *vrf_name);

/* Netlink functions */
void nl_msg_process(void *use_data, int sock, bool on_init);
void parse_nl_ip_address_msg_on_init(struct nlmsghdr *nlh, int msglen,
                                     struct shash *kernel_port_list);
void nl_add_ip_address(int cmd, const char *port_name, char *ip_address,
                       int family, bool secondary);

void portd_config_iprouting(const char *vrf_name, int enable);
void
portd_config_src_routing(struct vrf *vrf, const char *port_name, bool enable);
void portd_reconfig_ipaddr(struct port *port, struct ovsrec_port *port_row);
void portd_del_ipaddr(struct port *port);
void portd_ipaddr_config_on_init(void);

/* Inter-VLAN functions */
void portd_add_vlan_interface(const char *parent_intf_name,
                              const char *vlan_intf_name,
                              const unsigned short vlan_tag);
void portd_del_vlan_interface(const char *vlan_intf_name);
struct vrf* get_vrf_for_port(const char *port_name);
/* Proxy ARP function */
void portd_config_proxy_arp(struct port *port, char *str, int enable);

/*Local proxy ARP function */
void portd_config_local_proxy_arp(struct port *port, char *str, int enable);

unsigned int portd_if_nametoindex(struct vrf *vrf, const char *name);

void portd_arbiter_init(void);
void portd_arbiter_run(void);
void portd_arbiter_port_run(const struct ovsrec_port *port,
                            struct smap *forwarding_state);
int
get_vrf_ns_from_table_id(const struct ovsdb_idl *idl, const int64_t table_id,
                         char* vrf_ns_name);
#endif /* PORTD_H_ */
