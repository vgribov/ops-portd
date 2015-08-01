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
 * File: l3portd.h
 */

#ifndef L3PORTD_H_
#define L3PORTD_H_

#include "hmap.h"
#include "shash.h"
#include "vswitch-idl.h"

#define L3PORTD_DISABLE_ROUTING 0
#define L3PORTD_ENABLE_ROUTING 1
#define L3PORTD_POLL_INTERVAL 5
#define L3PORTD_IPV4_MAX_LEN 32
#define L3PORTD_IPV6_MAX_LEN 128

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

struct port {
    struct hmap_node port_node; /* Element in struct vrf's "ports" hmap. */
    char *name;
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

void l3portd_exit_ipcfg(void);
void l3portd_init_ipcfg(void);
void l3portd_config_iprouting(int enable);
void l3portd_reconfig_ipaddr(struct port *port, struct ovsrec_port *port_row);
void l3portd_del_ipaddr(struct port *port);



#endif /* L3PORTD_H_ */
