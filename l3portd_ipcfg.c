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
 * File: l3portd_ipcfg.c
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

#include "hash.h"
#include "l3portd.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(l3portd_ipcfg);

extern unsigned int idl_seqno;

static int nl_ip_sock;

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
    int maxlen = (family == AF_INET) ? L3PORTD_IPV4_MAX_LEN :
                                       L3PORTD_IPV6_MAX_LEN;
    *prefixlen = maxlen;

    if ((p = strchr(ip_address, '/'))) {
        *p++ = '\0';
        *prefixlen = atoi(p);
    }
    if (*prefixlen > maxlen) {
        VLOG_DBG("Bad prefixlen %d > %d", *prefixlen, maxlen);
        return -1;
    }
    if (inet_pton(family, ip_address, prefix) == 0) {
        VLOG_DBG("%d inet_pton failed with %s", family, strerror(errno));
        return -1;
    }

    return 0;
}

/* HALON_TODO - ipv6 secondary address also shows up as primary in 'ip -6 addr show' - fix */
/* HALON_TODO - unable to delete ipv6 address using netlink - fix */

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
    VLOG_DBG("Netlink %s IP addr '%s' for port '%s'",
              (cmd == RTM_NEWADDR) ? "added" : "deleted", ip_address,
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

/* deletes ip address from kernel */
void
l3portd_del_ipaddr(struct port *port)
{
    struct net_address *addr, *next_addr;

    if (port->ip4_address) {
        l3portd_set_ipaddr(RTM_DELADDR, port, port->ip4_address, AF_INET, false);
    }
    if (port->ip6_address) {
        l3portd_set_ipaddr(RTM_DELADDR, port, port->ip6_address, AF_INET6, false);
    }
    HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node, &port->secondary_ip4addr) {
        l3portd_set_ipaddr(RTM_DELADDR, port, addr->address, AF_INET, false);
    }
    HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node, &port->secondary_ip6addr) {
        l3portd_set_ipaddr(RTM_DELADDR, port, addr->address, AF_INET6, false);
    }
}

/* Take care of add/delete/modify of v4/v6 address from db */
void
l3portd_reconfig_ipaddr(struct port *port, struct ovsrec_port *port_row)
{
    const struct ovsdb_idl_column *column;

    /*
     * Configure primary network addresses
     */
    if (port_row->ip4_address) {
        if (port->ip4_address) {
            if (strcmp(port->ip4_address, port_row->ip4_address) != 0) {
                l3portd_set_ipaddr(RTM_DELADDR, port, port->ip4_address,
                                   AF_INET, false);
                free(port->ip4_address);

                port->ip4_address = xstrdup(port_row->ip4_address);
                l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip4_address,
                                   AF_INET, false);
            }
        } else {
            port->ip4_address = xstrdup(port_row->ip4_address);
            l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip4_address,
                               AF_INET, false);
        }
    } else {
        if (port->ip4_address != NULL) {
            l3portd_set_ipaddr(RTM_DELADDR, port, port->ip4_address,
                               AF_INET, false);
            free(port->ip4_address);
            port->ip4_address = NULL;
        }
    }

    if (port_row->ip6_address) {
        if (port->ip6_address) {
            if (strcmp(port->ip6_address, port_row->ip6_address) !=0) {
                l3portd_set_ipaddr(RTM_DELADDR, port, port->ip6_address,
                                   AF_INET6, false);
                free(port->ip6_address);

                port->ip6_address = xstrdup(port_row->ip6_address);
                l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip6_address,
                                   AF_INET6, false);
            }
        } else {
            port->ip6_address = xstrdup(port_row->ip6_address);
            l3portd_set_ipaddr(RTM_NEWADDR, port, port->ip6_address,
                               AF_INET6, false);
        }
    } else {
        if (port->ip6_address != NULL) {
            l3portd_set_ipaddr(RTM_DELADDR, port, port->ip6_address,
                               AF_INET6, false);
            free(port->ip6_address);
            port->ip6_address = NULL;
        }
    }

    /*
     * Configure secondary network addresses
     */
    OVSREC_IDL_GET_COLUMN(column, port_row, "ip4_address_secondary");
    if (column) {
        if (OVSREC_IDL_IS_COLUMN_MODIFIED(column, idl_seqno) ) {
            VLOG_DBG("ip4_address_secondary modified");
            l3portd_config_secondary_ipv4_addr(port, port_row);
        }
    }

    OVSREC_IDL_GET_COLUMN(column, port_row, "ip6_address_secondary");
    if (column) {
        if (OVSREC_IDL_IS_COLUMN_MODIFIED(column, idl_seqno) ) {
            VLOG_INFO("ip6_address_secondary modified");
            l3portd_config_secondary_ipv6_addr(port, port_row);
        }
    }

}
