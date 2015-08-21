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
 * File: portd_l3.c
 */

#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_addr.h>
#include <unistd.h>
#include <assert.h>

#include "hash.h"
#include "l3portd.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(portd_l3);

extern unsigned int idl_seqno;
extern struct ovsdb_idl *idl;
extern struct ovsdb_idl_txn *txn;
extern bool commit_txn;

static int nl_ip_sock;
static int l3portd_get_prefix(int family, char *ip_address, void *prefix,
                              unsigned char *prefixlen);

/*********** Begin Connected routes handling **************/

static void
apply_mask_ipv6 (struct prefix_ipv6 *p)
{
    u_char *pnt;
    int index;
    int offset;
    static u_char maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
                                0xf8, 0xfc, 0xfe, 0xff};

    index = p->prefixlen / 8;

    if (index < 16) {
        pnt = (u_char *) &p->prefix;
        offset = p->prefixlen % 8;

        pnt[index] &= maskbit[offset];
        index++;

        while (index < 16) {
            pnt[index++] = 0;
        }
    }
}

/* Convert masklen into IP address's netmask (network byte order). */
static void
masklen2ip (const int masklen, struct in_addr *netmask)
{
    assert (masklen >= 0 && masklen <= L3PORTD_IPV4_MAX_LEN);

    /* left shift is only defined for less than the size of the type.
     * we unconditionally use long long in case the target platform
     * has defined behaviour for << 32 (or has a 64-bit left shift) */
    if (sizeof(unsigned long long) > 4) {
        netmask->s_addr = htonl(0xffffffffULL << (32 - masklen));
    } else {
        netmask->s_addr = htonl(masklen ? 0xffffffffU << (32 - masklen) : 0);
    }
}

/* Apply mask to IPv4 prefix (network byte order). */
static void
apply_mask_ipv4 (struct prefix_ipv4 *p)
{
    struct in_addr mask;
    masklen2ip(p->prefixlen, &mask);
    p->prefix.s_addr &= mask.s_addr;
}

/*
 * Add a directly connected route to the DB. The NH is the port which
 * will be the egress port for the subnet
 */
static int
l3portd_add_connected_route (struct ovsrec_port *ovs_port, bool is_v4)
{
    const struct ovsrec_route *row = NULL;
    const struct ovsrec_vrf *row_vrf = NULL;
    struct ovsrec_nexthop *row_nh = NULL;

    const bool selected = true;
    char prefix_str[256];
    int64_t distance = CONNECTED_ROUTE_DISTANCE;
    int retval;

    /*
     * HALON_TODO: For now we support only 1 VRF in the system.
     * When we have support for multiple VRF, then fetch the
     * correct VRF for the port
     */
    row_vrf = ovsrec_vrf_first(idl);
    if(!row_vrf) {
        VLOG_ERR("No vrf information yet.");
        return -1;
    }
    /*
     * Populate the route row
     */
    row = ovsrec_route_insert(txn);
    ovsrec_route_set_vrf(row, row_vrf);
    if (is_v4) {
        struct prefix_ipv4 v4_prefix;
        char buf[INET_ADDRSTRLEN];

        ovsrec_route_set_address_family(row,
                        OVSREC_ROUTE_ADDRESS_FAMILY_IPV4);
        /*
         * Conversion to prefix format is a 3 step process:
         * - Convert the IP address string to prefix format.
         * - Apply the mask i.e. A.B.C.D/24 to A.B.C.0/24
         * - Convert it back to string to write to DB
         */
        retval = l3portd_get_prefix(AF_INET, ovs_port->ip4_address,
                                    &v4_prefix.prefix, &v4_prefix.prefixlen);
        if (retval) {
            VLOG_ERR("Error converting DB string to prefix: %s",
                     ovs_port->ip4_address);
            return retval;
        }
        apply_mask_ipv4(&v4_prefix);

        inet_ntop (AF_INET, &(v4_prefix.prefix), buf, INET_ADDRSTRLEN);
        snprintf (prefix_str, INET_PREFIX_SIZE,
                  "%s/%d", buf, v4_prefix.prefixlen);

        ovsrec_route_set_prefix(row, (const char *)prefix_str);
    } else {
        struct prefix_ipv6 v6_prefix;
        char buf[INET6_ADDRSTRLEN];

        ovsrec_route_set_address_family(row,
                        OVSREC_ROUTE_ADDRESS_FAMILY_IPV6);
        /*
         * Conversion to prefix format is a 3 step process:
         * - Convert the IP address string to prefix format.
         * - Apply the mask i.e. A.B.C.D/24 to A.B.C.0/24
         * - Convert it back to string to write to DB
         */
        retval = l3portd_get_prefix(AF_INET6, ovs_port->ip6_address,
                                    &v6_prefix.prefix, &v6_prefix.prefixlen);
        if (retval) {
            VLOG_ERR("Error converting DB string to prefix: %s",
                     ovs_port->ip6_address);
            return retval;
        }
        apply_mask_ipv6(&v6_prefix);

        inet_ntop (AF_INET6, &(v6_prefix.prefix), buf, INET6_ADDRSTRLEN);
        snprintf (prefix_str, INET6_PREFIX_SIZE,
                  "%s/%d", buf, v6_prefix.prefixlen);

        ovsrec_route_set_prefix(row, (const char *)prefix_str);
    }
    ovsrec_route_set_sub_address_family(row,
                        OVSREC_ROUTE_SUB_ADDRESS_FAMILY_UNICAST);
    ovsrec_route_set_from(row, OVSREC_ROUTE_FROM_CONNECTED);
    /*
     * Connected routes have a distance of 0
     */
    ovsrec_route_set_distance(row, &distance, 1);
    /*
     * Set the selected bit to true for the route entry
     */
    ovsrec_route_set_selected(row, &selected, 1);

    /*
     * Populate the Nexthop row
     */
    row_nh = ovsrec_nexthop_insert(txn);

    ovsrec_nexthop_set_ports(row_nh, &ovs_port, row_nh->n_ports + 1);

    /*
     * Update the route entry with the new nexthop
     */
    ovsrec_route_set_nexthops(row, &row_nh, row->n_nexthops + 1);

    commit_txn = true;

    return 0;
}

static bool
is_route_matched (const struct ovsrec_route *row_route, char *prefix_str,
                  char *port_name)
{
    if (!strcmp(row_route->prefix, prefix_str) &&
        !strcmp(row_route->from, OVSREC_ROUTE_FROM_CONNECTED) &&
        (row_route->sub_address_family == NULL ||
         !strcmp(row_route->sub_address_family,
                OVSREC_ROUTE_SUB_ADDRESS_FAMILY_UNICAST)) &&
        !strcmp(row_route->nexthops[0]->ports[0]->name, port_name)) {
        return true;
    }
    return false;
}

/*
 * Delete a directly connected route to the DB. The NH is the port which
 * will be the egress port for the subnet
 */
static int
l3portd_del_connected_route (char *address, char *port_name, bool is_v4)
{
    int retval;
    char prefix_str[256];
    const struct ovsrec_route *row_route = NULL;

    /*
     * Get the ip address from the port and convert it to the
     * prefix format
     */
    if (is_v4) {
        struct prefix_ipv4 v4_prefix;
        char buf[INET_ADDRSTRLEN];
        /*
         * Conversion to prefix format is a 3 step process:
         * - Convert the IP address string to prefix format.
         * - Apply the mask i.e. A.B.C.D/24 to A.B.C.0/24
         * - Convert it back to string
         */
        retval = l3portd_get_prefix(AF_INET, address, &v4_prefix.prefix,
                                    &v4_prefix.prefixlen);
        if (retval) {
            VLOG_ERR("Error converting DB string to prefix: %s", address);
            return retval;
        }
        apply_mask_ipv4(&v4_prefix);

        inet_ntop (AF_INET, &(v4_prefix.prefix), buf, INET_ADDRSTRLEN);
        snprintf (prefix_str, INET_PREFIX_SIZE,
                  "%s/%d", buf, v4_prefix.prefixlen);

        OVSREC_ROUTE_FOR_EACH(row_route, idl) {
            if (row_route->address_family != NULL) {
                if (strcmp(row_route->address_family, "ipv4")) {
                    continue;
                }
            }
            if (is_route_matched(row_route, prefix_str, port_name)) {
                /*
                 * Found the row. Delete the route and its nexthop
                 */
                ovsrec_nexthop_delete(row_route->nexthops[0]);
                ovsrec_route_delete(row_route);
                commit_txn = true;
                return 0;
            }
        }
    } else {
        struct prefix_ipv6 v6_prefix;
        char buf[INET6_ADDRSTRLEN];
        /*
         * Conversion to prefix format is a 3 step process:
         * - Convert the IP address string to prefix format.
         * - Apply the mask i.e. A.B.C.D/24 to A.B.C.0/24
         * - Convert it back to string
         */
        retval = l3portd_get_prefix(AF_INET6, address, &v6_prefix.prefix,
                                    &v6_prefix.prefixlen);
        if (retval) {
            VLOG_ERR("Error converting DB string to prefix: %s", address);
            return retval;
        }
        apply_mask_ipv6(&v6_prefix);

        inet_ntop (AF_INET6, &(v6_prefix.prefix), buf, INET6_ADDRSTRLEN);
        snprintf (prefix_str, INET6_PREFIX_SIZE,
                  "%s/%d", buf, v6_prefix.prefixlen);

        OVSREC_ROUTE_FOR_EACH(row_route, idl) {
            if (row_route->address_family == NULL ||
                strcmp(row_route->address_family, "ipv6")) {
                /*
                 * Skip NULL and non ipv6 address families
                 */
                continue;
            }
            if (is_route_matched(row_route, prefix_str, port_name)) {
                /*
                 * Found the row. Delete the route and its nexthop
                 */
                ovsrec_nexthop_delete(row_route->nexthops[0]);
                ovsrec_route_delete(row_route);
                commit_txn = true;
                return 0;
            }
        }
    }
    /*
     * We should have found an entry and returned before we hit the end
     */
    VLOG_ERR("Connected route not found for port %s",port_name);
    return -1;
}

/*********** End Connected routes handling **************/

static
int l3portd_netlink_socket_open(void)
{
    struct sockaddr_nl s_addr;

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (sock < 0) {
        return sock;
    }

    memset((void *) &s_addr, 0, sizeof(s_addr));
    s_addr.nl_family = AF_NETLINK;
    s_addr.nl_pid = getpid();
    s_addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (bind(sock, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
        return -1;
    }

    return sock;
}

static
void l3portd_netlink_socket_close(int socket)
{
    close(socket);
}

void
l3portd_exit_ipcfg(void)
{
    l3portd_netlink_socket_close(nl_ip_sock);
}

void
l3portd_init_ipcfg(void)
{
    nl_ip_sock = l3portd_netlink_socket_open();
}

/* write to /proc entries to enable/disable Linux ip forwarding(routing) */
void
l3portd_config_iprouting(int enable)
{
    int fd = -1, nbytes = 0;
    char buf[16];
    const char *ipv4_path = "/proc/sys/net/ipv4/ip_forward";
    const char *ipv6_path = "/proc/sys/net/ipv6/conf/all/forwarding";

    nbytes = sprintf(buf, "%d", enable);

    if ((fd = open(ipv4_path, O_WRONLY)) == -1) {
        VLOG_ERR("Unable to open %s (%s)", ipv4_path, strerror(errno));
        return;
    }
    if (write(fd, buf, nbytes) == -1) {
        VLOG_ERR("Unable to write to %s (%s)", ipv4_path, strerror(errno));
        close(fd);
        return;
    }
    close(fd);
    VLOG_DBG("%s ipv4 forwarding", (enable == 1 ? "Enabled" : "Disabled"));

    if ((fd = open(ipv6_path, O_WRONLY)) == -1) {
        VLOG_ERR("Unable to open %s (%s)", ipv6_path, strerror(errno));
        return;
    }
    if (write(fd, buf, nbytes) == -1) {
        VLOG_ERR("Unable to write to %s (%s)", ipv6_path, strerror(errno));
        close(fd);
        return;
    }
    close(fd);
    VLOG_DBG("%s ipv6 forwarding", (enable == 1 ? "Enabled" : "Disabled"));
}

/* return ipv4/ipv6 prefix and prefix length */
static int
l3portd_get_prefix(int family, char *ip_address, void *prefix,
                   unsigned char *prefixlen)
{
    char *p;
    char *ip_address_copy;
    int maxlen = (family == AF_INET) ? L3PORTD_IPV4_MAX_LEN :
                                       L3PORTD_IPV6_MAX_LEN;
    *prefixlen = maxlen;

    /*
     * Make a copy of the IP/IPv6 address.
     */
    ip_address_copy = xstrdup(ip_address);

    /*
     * Extract the mask length of the address.
     */
    if ((p = strchr(ip_address_copy, '/'))) {
        *p++ = '\0';
        *prefixlen = atoi(p);
    }

    /*
     * If the extracted mask length is greater
     * than 'maxlen', then free the memory in
     * 'ip_address_copy' and return -1.
     */
    if (*prefixlen > maxlen) {
        VLOG_DBG("Bad prefixlen %d > %d", *prefixlen, maxlen);
        free(ip_address_copy);
        return -1;
    }

    /*
     * If the extraction of the prefix fails, then
     * free the memory in 'ip_address_copy' and return -1.
     */
    if (inet_pton(family, ip_address_copy, prefix) == 0) {
        VLOG_DBG("%d inet_pton failed with %s", family, strerror(errno));
        free(ip_address_copy);
        return -1;
    }

    /*
     * In case of successful extraction,
     * free the memory in 'ip_address_copy'
     * and return 0.
     */
    free(ip_address_copy);
    return 0;
}

/* HALON_TODO - ipv6 secondary address also shows up as primary in 'ip -6 addr show' - fix */

/* Set IP address on Linux interface using netlink sockets */
static void
l3portd_set_ipaddr(int cmd, struct port *port, char *ip_address,
                   int family, bool secondary)
{
    int buflen;
    struct rtattr *rta;
    int bytelen;
    struct {
        struct nlmsghdr n;
        struct ifaddrmsg ifa;
        char buf[128];
    } req;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    unsigned char prefixlen, *ipaddr = NULL;

    memset (&req, 0, sizeof(req));

    bytelen = (family == AF_INET ? 4 : 16);

    req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type = cmd;

    req.ifa.ifa_family = family;
    req.ifa.ifa_index = if_nametoindex(port->name);
    if (req.ifa.ifa_index == 0) {
        VLOG_ERR("Unable to get ifindex for port '%s'", port->name);
        return;
    }
    if (family == AF_INET) {
        if (l3portd_get_prefix(AF_INET, ip_address, &ipv4, &prefixlen) == -1) {
            VLOG_ERR("Unable to get prefix info for '%s'", ip_address);
            return;
        }
        ipaddr = (unsigned char *)&ipv4;
    } else if (family == AF_INET6) {
        if (l3portd_get_prefix(AF_INET6, ip_address, &ipv6, &prefixlen) == -1) {
            VLOG_ERR("Unable to get prefix info for '%s'", ip_address);
            return;
        }
        ipaddr = (unsigned char *)&ipv6;
    }
    req.ifa.ifa_prefixlen = prefixlen;

    if (secondary) {
        req.ifa.ifa_flags |=  IFA_F_SECONDARY;
    }

    buflen = RTA_LENGTH(bytelen);
    if (NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(buflen) > sizeof(req)) {
        VLOG_ERR("Message length (%d) exceeded max (%d)",
                NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(buflen), (int)sizeof(req));
        return;
    }

    rta = NLMSG_TAIL(&req.n);
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = buflen;
    memcpy(RTA_DATA(rta), ipaddr, bytelen);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(buflen);

    if (send(nl_ip_sock, &req, req.n.nlmsg_len, 0) == -1) {
        VLOG_ERR("Netlink failed to set IP address for '%s'", ip_address);
        return;
    }

    VLOG_DBG("Netlink %s IP addr '%s' and mask length = %u (%s) for port '%s'",
             (cmd == RTM_NEWADDR) ? "added" : "deleted",
             ip_address, prefixlen, secondary ? "secondary":"primary",
             port->name);
}

static struct net_address *
l3portd_ip6_addr_find(struct port *cfg, const char *address)
{
    struct net_address *addr;

    HMAP_FOR_EACH_WITH_HASH (addr, addr_node, hash_string(address, 0),
                             &cfg->secondary_ip6addr) {
        if (!strcmp(addr->address, address)) {
            return addr;
        }
    }

    return NULL;
}

static struct net_address *
l3portd_ip4_addr_find(struct port *cfg, const char *address)
{
    struct net_address *addr;

    HMAP_FOR_EACH_WITH_HASH (addr, addr_node, hash_string(address, 0),
                             &cfg->secondary_ip4addr) {
        if (!strcmp(addr->address, address)) {
            return addr;
        }
    }

    return NULL;
}

/* Add secondary v6 address in Linux that got added.
 * Delete secondary v6 addresses from Linux that got deleted.
 */
static void
l3portd_config_secondary_ipv6_addr(struct port *port,
                                       struct ovsrec_port *port_row)
{
    struct shash new_ip6_list;
    struct net_address *addr, *next;
    struct shash_node *addr_node;
    int i;

    shash_init(&new_ip6_list);

    /*
     * Collect the interested network addresses
     */
    for (i = 0; i < port_row->n_ip6_address_secondary; i++) {
        if(!shash_add_once(&new_ip6_list, port_row->ip6_address_secondary[i],
                           port_row->ip6_address_secondary[i])) {
            VLOG_WARN("Duplicate address in secondary list %s\n",
                      port_row->ip6_address_secondary[i]);
        }
    }

    /*
     * Parse the existing list of addresses and remove obsolete ones
     */
    HMAP_FOR_EACH_SAFE (addr, next, addr_node, &port->secondary_ip6addr) {
        if (!shash_find_data(&new_ip6_list, addr->address)) {
            hmap_remove(&port->secondary_ip6addr, &addr->addr_node);
            l3portd_set_ipaddr(RTM_DELADDR, port, addr->address, AF_INET6, true);
            free(addr->address);
            free(addr);
        }
    }

    /*
     * Add the newly added addresses to the list
     */
    SHASH_FOR_EACH (addr_node, &new_ip6_list) {
        struct net_address *addr;
        const char *address = addr_node->data;
        if (!l3portd_ip6_addr_find(port, address)) {
            /*
             * Add the new address to the list
             */
            addr = xzalloc(sizeof *addr);
            addr->address = xstrdup(address);
            hmap_insert(&port->secondary_ip6addr, &addr->addr_node,
                        hash_string(addr->address, 0));
            l3portd_set_ipaddr(RTM_NEWADDR, port, addr->address, AF_INET6, true);
        }
    }
}


/* Add secondary v4 address in Linux that got added in db.
 * Delete secondary v4 addresses from Linux that got deleted from db.
 */
static void
l3portd_config_secondary_ipv4_addr(struct port *port,
                                   struct ovsrec_port *port_row)
{
    struct shash new_ip_list;
    struct net_address *addr, *next;
    struct shash_node *addr_node;
    int i;

    shash_init(&new_ip_list);

    /*
     * Collect the interested network addresses
     */
    for (i = 0; i < port_row->n_ip4_address_secondary; i++) {
        if(!shash_add_once(&new_ip_list, port_row->ip4_address_secondary[i],
                           port_row->ip4_address_secondary[i])) {
            VLOG_WARN("Duplicate address in secondary list %s\n",
                      port_row->ip4_address_secondary[i]);
        }
    }

    /*
     * Parse the existing list of addresses and remove obsolete ones
     */
    HMAP_FOR_EACH_SAFE (addr, next, addr_node, &port->secondary_ip4addr) {
        if (!shash_find_data(&new_ip_list, addr->address)) {
            hmap_remove(&port->secondary_ip4addr, &addr->addr_node);
            l3portd_set_ipaddr(RTM_DELADDR, port, addr->address, AF_INET, true);
            free(addr->address);
            free(addr);
        }
    }

    /*
     * Add the newly added addresses to the list
     */
    SHASH_FOR_EACH (addr_node, &new_ip_list) {
        struct net_address *addr;
        const char *address = addr_node->data;
        if (!l3portd_ip4_addr_find(port, address)) {
            /*
             * Add the new address to the list
             */
            addr = xzalloc(sizeof *addr);
            addr->address = xstrdup(address);
            hmap_insert(&port->secondary_ip4addr, &addr->addr_node,
                        hash_string(addr->address, 0));
            l3portd_set_ipaddr(RTM_NEWADDR, port, addr->address, AF_INET, true);
        }
    }
}

/**
 * This function adds ipv4 address on a given port to kernel.
 */
void
l3portd_add_ipv4_addr(struct port *port)
{
    struct net_address *addr, *next_addr;

    if (!port) {
        VLOG_DBG("The port on which the addresses need to be added into "
                 "kernel is null\n");
        return;
    }

    if (port->ip4_address) {
        l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip4_address, AF_INET,
                           false);
    }

    HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node, &port->secondary_ip4addr) {
        l3portd_set_ipaddr(RTM_NEWADDR, port, addr->address, AF_INET, true);
    }
}

/**
 * This function adds ipv6 address on a given port to kernel.
 */
void
l3portd_add_ipv6_addr(struct port *port)
{
    struct net_address *addr, *next_addr;

    if (!port) {
        VLOG_DBG("The port on which the addresses need to be added into "
                 "kernel is null\n");
        return;
    }

    if (port->ip6_address) {
        l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip6_address, AF_INET6,
                           false);
    }

    HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node, &port->secondary_ip6addr) {
        l3portd_set_ipaddr(RTM_NEWADDR, port, addr->address, AF_INET6, true);
    }
}

/**
 * This functionn adds both ipv4 and ipv6 addresses on a given port to kernel
 */
void
l3portd_add_ipaddr(struct port *port)
{
    l3portd_add_ipv4_addr(port);
    l3portd_add_ipv6_addr(port);
}

/**
 * This function deletes ipv4 address on a given port from kernel
 */
void
l3portd_del_ipv4_addr(struct port *port)
{
    struct net_address *addr, *next_addr;

    if (!port) {
        VLOG_DBG("The port on which the addresses need to be deleted into "
                 "kernel is null\n");
        return;
    }

    if (port->ip4_address) {
        l3portd_set_ipaddr(RTM_DELADDR, port, port->ip4_address, AF_INET,
                           false);
    }

    HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node, &port->secondary_ip4addr) {
        l3portd_set_ipaddr(RTM_DELADDR, port, addr->address, AF_INET, true);
    }
}

/**
 * This function deletes ipv6 address on a given port from kernel
 */
void
l3portd_del_ipv6_addr(struct port *port)
{
    struct net_address *addr, *next_addr;

    if (!port) {
        VLOG_DBG("The port on which the addresses need to be deleted into "
                 "kernel is null\n");
        return;
    }

    if (port->ip6_address) {
        l3portd_set_ipaddr(RTM_DELADDR, port, port->ip6_address, AF_INET6,
                           false);
    }

    HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node, &port->secondary_ip6addr) {
        l3portd_set_ipaddr(RTM_DELADDR, port, addr->address, AF_INET6, true);
    }
}

/**
 * This function deletes both ipv4 and ipv6 address on a given port
 * from kernel
 */
void
l3portd_del_ipaddr(struct port *port)
{
    l3portd_del_ipv4_addr(port);
    l3portd_del_ipv6_addr(port);
}

/* Take care of add/delete/modify of v4/v6 address from db */
void
l3portd_reconfig_ipaddr(struct port *port, struct ovsrec_port *port_row)
{
    /*
     * Configure primary network addresses
     */
    if (port_row->ip4_address) {
        if (port->ip4_address) {
            if (strcmp(port->ip4_address, port_row->ip4_address) != 0) {
                l3portd_set_ipaddr(RTM_DELADDR, port, port->ip4_address,
                                   AF_INET, false);
                /*
                 * Delete the old route
                 */
                l3portd_del_connected_route(port->ip4_address, port->name, true);
                free(port->ip4_address);

                port->ip4_address = xstrdup(port_row->ip4_address);
                l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip4_address,
                                   AF_INET, false);
                /*
                 * Add the new route
                 */
                l3portd_add_connected_route(port_row, true);
            }
        } else {
            port->ip4_address = xstrdup(port_row->ip4_address);
            l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip4_address,
                               AF_INET, false);
            /*
             * Add a new route
             */
            l3portd_add_connected_route(port_row, true);
        }
    } else {
        if (port->ip4_address != NULL) {
            l3portd_set_ipaddr(RTM_DELADDR, port, port->ip4_address,
                               AF_INET, false);
            /*
             * Delete the route
             */
            l3portd_del_connected_route(port->ip4_address, port->name, true);
            free(port->ip4_address);
            port->ip4_address = NULL;
        }
    }

    if (port_row->ip6_address) {
        if (port->ip6_address) {
            if (strcmp(port->ip6_address, port_row->ip6_address) !=0) {
                l3portd_set_ipaddr(RTM_DELADDR, port, port->ip6_address,
                                   AF_INET6, false);
                /*
                 * Delete the old route
                 */
                l3portd_del_connected_route(port->ip6_address, port->name, false);
                free(port->ip6_address);

                port->ip6_address = xstrdup(port_row->ip6_address);
                l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip6_address,
                                   AF_INET6, false);
                /*
                 * Add the new route
                 */
                l3portd_add_connected_route(port_row, false);
            }
        } else {
            port->ip6_address = xstrdup(port_row->ip6_address);
            l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip6_address,
                               AF_INET6, false);
            /*
             * Add the new route
             */
            l3portd_add_connected_route(port_row, false);
        }
    } else {
        if (port->ip6_address != NULL) {
            l3portd_set_ipaddr(RTM_DELADDR, port, port->ip6_address,
                               AF_INET6, false);
            /*
             * Delete the route
             */
            l3portd_del_connected_route(port->ip6_address, port->name, false);
            free(port->ip6_address);
            port->ip6_address = NULL;
        }
    }

    /*
     * Configure secondary network addresses
     */
    if (OVSREC_IDL_IS_COLUMN_MODIFIED(ovsrec_port_col_ip4_address_secondary,
                                      idl_seqno) ) {
        VLOG_DBG("ip4_address_secondary modified");
        l3portd_config_secondary_ipv4_addr(port, port_row);
    }

    if (OVSREC_IDL_IS_COLUMN_MODIFIED(ovsrec_port_col_ip6_address_secondary,
                                      idl_seqno) ) {
        VLOG_DBG("ip6_address_secondary modified");
        l3portd_config_secondary_ipv6_addr(port, port_row);
    }

}
