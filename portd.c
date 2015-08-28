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
 * File: portd.c
 */

/* This daemon handles the following functionality:
 * - Allocating internal VLAN for L3 interface.
 * - Configuring IP address for L3 interface.
 * - Enable/disable IP routing
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* OVSDB Includes */
#include "config.h"
#include "command-line.h"
#include "stream.h"
#include "daemon.h"
#include "fatal-signal.h"
#include "dirs.h"
#include "poll-loop.h"
#include "unixctl.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "vswitch-idl.h"
#include "openhalon-idl.h"
#include "openhalon-dflt.h"
#include "coverage.h"
#include "hash.h"
#include "svec.h"

#include "portd.h"

VLOG_DEFINE_THIS_MODULE(portd);
COVERAGE_DEFINE(portd_reconfigure);

extern int nl_ip_sock;
unsigned int idl_seqno;
struct ovsdb_idl *idl;
struct ovsdb_idl_txn *txn;
bool commit_txn = false;

static unixctl_cb_func portd_unixctl_dump;
static int system_configured = false;

/* All vrfs, indexed by name. */
static struct hmap all_vrfs = HMAP_INITIALIZER(&all_vrfs);

static inline void
portd_chk_for_system_configured(void)
{
    const struct ovsrec_open_vswitch *ovs_vsw = NULL;

    if (system_configured) {
        /* Nothing to do if we're already configured. */
        return;
    }

    ovs_vsw = ovsrec_open_vswitch_first(idl);

    if (ovs_vsw && (ovs_vsw->cur_cfg > (int64_t) 0)) {
        system_configured = true;
        VLOG_INFO("System is now configured (cur_cfg=%d).",
                (int)ovs_vsw->cur_cfg);
    }

}

/* Register for port table notifications so that:
 * When port is marked L3 (by attaching to VRF), create an internal VLAN for it.
 * When port is not L3, delete the internal VLAN associated with it.
 * When IP address (primary, secondary) are configured on the port,
 *      configure the IP in Linux kernel interfaces using netlink sockets.
 * When IP addresses are removed/modified, reflect the same in Linux.
 * When VRF is added/deleted, enable/disable Linux forwarding (routing).
 * When Interface transitions its admin state.
 */
static void
portd_init(const char *remote)
{
    idl = ovsdb_idl_create(remote, &ovsrec_idl_class, false, true);
    idl_seqno = ovsdb_idl_get_seqno(idl);
    ovsdb_idl_set_lock(idl, "halon_portd");
    ovsdb_idl_verify_write_only(idl);

    ovsdb_idl_add_table(idl, &ovsrec_table_subsystem);
    ovsdb_idl_add_column(idl, &ovsrec_subsystem_col_other_info);

    ovsdb_idl_add_table(idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(idl, &ovsrec_open_vswitch_col_cur_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_open_vswitch_col_other_config);

    ovsdb_idl_add_table(idl, &ovsrec_table_vrf);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_ports);

    ovsdb_idl_add_table(idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_vlans);
    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_vlans);

    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_hw_config);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_hw_config);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_ip4_address);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_ip4_address_secondary);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_ip6_address);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_ip6_address_secondary);

    /*
     * Adding the interface table so that we can listen to interface
     * "up"/"down" notifications. We need to add two columns to the
     * interface table:-
     * 1. Interface name for finding which port corresponding to the
     *    interface went "up"/"down".
     * 2. Interface admin state.
     */
    ovsdb_idl_add_table(idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_admin_state);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_user_config);

    ovsdb_idl_add_table(idl, &ovsrec_table_vlan);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_name);
    ovsdb_idl_omit_alert(idl, &ovsrec_vlan_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_id);
    ovsdb_idl_omit_alert(idl, &ovsrec_vlan_col_id);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_admin);
    ovsdb_idl_omit_alert(idl, &ovsrec_vlan_col_admin);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_oper_state);
    ovsdb_idl_omit_alert(idl, &ovsrec_vlan_col_oper_state);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_oper_state_reason);
    ovsdb_idl_omit_alert(idl, &ovsrec_vlan_col_oper_state_reason);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_internal_usage);
    ovsdb_idl_omit_alert(idl, &ovsrec_vlan_col_internal_usage);

    /*
     * This daemon is also responsible for adding routes for
     * directly connected subnets.
     */
    ovsdb_idl_add_table(idl, &ovsrec_table_nexthop);
    ovsdb_idl_add_column(idl, &ovsrec_nexthop_col_ports);
    ovsdb_idl_omit_alert(idl, &ovsrec_nexthop_col_ports);

    ovsdb_idl_add_table(idl, &ovsrec_table_route);
    ovsdb_idl_add_column(idl, &ovsrec_route_col_prefix);
    ovsdb_idl_omit_alert(idl, &ovsrec_route_col_prefix);
    ovsdb_idl_add_column(idl, &ovsrec_route_col_from);
    ovsdb_idl_omit_alert(idl, &ovsrec_route_col_from);
    ovsdb_idl_add_column(idl, &ovsrec_route_col_nexthops);
    ovsdb_idl_omit_alert(idl, &ovsrec_route_col_nexthops);
    ovsdb_idl_add_column(idl, &ovsrec_route_col_address_family);
    ovsdb_idl_omit_alert(idl, &ovsrec_route_col_address_family);
    ovsdb_idl_add_column(idl, &ovsrec_route_col_sub_address_family);
    ovsdb_idl_omit_alert(idl, &ovsrec_route_col_sub_address_family);
    ovsdb_idl_add_column(idl, &ovsrec_route_col_distance);
    ovsdb_idl_omit_alert(idl, &ovsrec_route_col_distance);
    ovsdb_idl_add_column(idl, &ovsrec_route_col_vrf);
    ovsdb_idl_omit_alert(idl, &ovsrec_route_col_vrf);
    ovsdb_idl_add_column(idl, &ovsrec_route_col_selected);
    ovsdb_idl_omit_alert(idl, &ovsrec_route_col_selected);

    unixctl_command_register("portd/dump", "", 0, 0,
                             portd_unixctl_dump, NULL);

    portd_init_ipcfg();
}

static void
portd_exit(void)
{
    portd_exit_ipcfg();
    ovsdb_idl_destroy(idl);
}

static struct vrf*
portd_vrf_lookup(const char *name)
{
    struct vrf *vrf;

    HMAP_FOR_EACH_WITH_HASH (vrf, node, hash_string(name, 0), &all_vrfs) {
        if (!strcmp(vrf->name, name)) {
            return vrf;
        }
    }
    return NULL;
}

/* delete internal port cache */
static void
portd_port_destroy(struct port *port)
{
    if (port) {
        struct vrf *vrf = port->vrf;
        struct net_address *addr, *next_addr;

        VLOG_DBG("port '%s' destroy", port->name);
        if (port->ip4_address) {
            free(port->ip4_address);
        }
        if (port->ip6_address) {
            free(port->ip6_address);
        }

        HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node,
                            &port->secondary_ip4addr) {
            free(addr->address);
            free(addr);
        }
        hmap_destroy(&port->secondary_ip4addr);

        HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node,
                            &port->secondary_ip6addr) {
            free(addr->address);
            free(addr);
        }
        hmap_destroy(&port->secondary_ip6addr);

        hmap_remove(&vrf->ports, &port->port_node);
        free(port->name);
        free(port);
    }
}

/* delete vlan from VLAN table in DB */
static void
portd_bridge_del_vlan(struct ovsrec_bridge *br, struct ovsrec_vlan *vlan)
{
    struct ovsrec_vlan **vlans;
    size_t i, n;

    VLOG_DBG("Deleting VLAN %d", (int)vlan->id);
    vlans = xmalloc(sizeof *br->vlans * br->n_vlans);
    for (i = n = 0; i < br->n_vlans; i++) {
        if (br->vlans[i] != vlan) {
            vlans[n++] = br->vlans[i];
        }
    }
    ovsrec_bridge_set_vlans(br, vlans, n);
    commit_txn = true;
    free(vlans);
}

static void
portd_del_internal_vlan(int internal_vid)
{
    int i;
    struct ovsrec_vlan *vlan = NULL;
    const struct ovsrec_bridge *br_row = NULL;
    if (internal_vid == -1) {
        return;
    }

    OVSREC_BRIDGE_FOR_EACH (br_row, idl) {
        if (!strcmp(br_row->name, DEFAULT_BRIDGE_NAME)) {
            for (i = 0; i < br_row->n_vlans; i++) {
                if (internal_vid == br_row->vlans[i]->id) {
                    vlan = br_row->vlans[i];
                    portd_bridge_del_vlan((struct ovsrec_bridge *)br_row, vlan);
                }
            }
        }
    }
}

/**
 * This function returns the 'port' structure corresponding to a
 * port 'name' in a given 'vrf'. If the port does not not exist
 * within the 'vrf', then this function will return 'NULL'.
 */
static struct port*
portd_port_lookup(const struct vrf *vrf, const char *name)
{
    struct port *port;

    if (!vrf || !name) {
        VLOG_DBG("vrf is %s and port name is %s\n",
                 vrf ? vrf->name:"NULL",
                 name ? name:"NULL");
        return NULL;
    }

    HMAP_FOR_EACH_WITH_HASH (port, port_node, hash_string(name, 0),
                             &vrf->ports) {
        if (!strcmp(port->name, name)) {
            return port;
        }
    }

    return NULL;
}

/* delete vrf from cache */
static void
portd_vrf_del(struct vrf *vrf)
{
    if (vrf) {
        /* Delete all the associated ports before destroying vrf */
        struct port *port, *next_port;

        VLOG_DBG("Deleting vrf '%s'",vrf->name);

        HMAP_FOR_EACH_SAFE (port, next_port, port_node, &vrf->ports) {
            portd_del_internal_vlan(port->internal_vid);
            portd_del_ipaddr(port);
            portd_port_destroy(port);
        }
        hmap_remove(&all_vrfs, &vrf->node);
        hmap_destroy(&vrf->ports);
        free(vrf->name);
        free(vrf);
    }
}

/* add vrf into cache */
static void
portd_vrf_add(const struct ovsrec_vrf *vrf_row)
{
    struct vrf *vrf;

    ovs_assert(!portd_vrf_lookup(vrf_row->name));
    vrf = xzalloc(sizeof *vrf);

    vrf->name = xstrdup(vrf_row->name);
    vrf->cfg = vrf_row;

    hmap_init(&vrf->ports);
    hmap_insert(&all_vrfs, &vrf->node, hash_string(vrf->name, 0));

    VLOG_DBG("Added vrf '%s'",vrf_row->name);
}

static void
portd_add_del_vrf(void)
{
    struct vrf *vrf, *next;
    struct shash new_vrfs;
    const struct ovsrec_vrf *vrf_row = NULL;

    /* Collect new vrfs' names and types. */
    shash_init(&new_vrfs);
    OVSREC_VRF_FOR_EACH (vrf_row, idl) {
        shash_add_once(&new_vrfs, vrf_row->name, vrf_row);
    }

    /* Delete the vrfs' that are deleted from the db */
    HMAP_FOR_EACH_SAFE (vrf, next, node, &all_vrfs) {
        vrf->cfg = shash_find_data(&new_vrfs, vrf->name);
        if (!vrf->cfg) {
            portd_vrf_del(vrf);
            portd_config_iprouting(PORTD_DISABLE_ROUTING);
        }
    }

    /* Add new vrfs. */
    OVSREC_VRF_FOR_EACH (vrf_row, idl) {
        struct vrf *vrf = portd_vrf_lookup(vrf_row->name);
        if (!vrf) {
            portd_vrf_add(vrf_row);
            portd_config_iprouting(PORTD_ENABLE_ROUTING);
        }
    }

    shash_destroy(&new_vrfs);
}

static int
portd_change_if_state (const char *ifname, bool intf_up)
{
    struct ifreq ifr;

    int rc;
    struct {
        struct nlmsghdr n;
        struct ifinfomsg ifi;
        char buf[128];
    } req;

    memset(&req, 0, sizeof(req));

    /*
     * HALON_TODO: Convert the ioctl to netlink socket
     * messages to read the flags before writing it
     * back to the kernel
     */
    ioctl(nl_ip_sock, SIOCGIFFLAGS, &ifr);

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.n.nlmsg_type = RTM_SETLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST;

    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = if_nametoindex(ifname);
    if (intf_up == true) {
        req.ifi.ifi_flags = ifr.ifr_flags | IFF_UP;
    } else {
        req.ifi.ifi_flags = ifr.ifr_flags & ~IFF_UP;
    }
    req.ifi.ifi_change = 0xffffffff;

    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len);

    if (req.n.nlmsg_len > sizeof(req)) {
        VLOG_ERR("Message length (%d) exceeded max (%d)",
                 req.n.nlmsg_len, (int)sizeof(req));
    }

    rc = send(nl_ip_sock, &req, req.n.nlmsg_len, 0);
    if (rc < 0) {
        VLOG_ERR("Error sending interface state message");
    }
    return rc;
}

static void
portd_process_interface_admin_up_down_events (void)
{
    const struct ovsrec_interface *interface_row = NULL;
    bool int_up = false;
    struct smap user_config;
    const char *admin_status;

    if (OVSREC_IDL_IS_COLUMN_MODIFIED(
               ovsrec_interface_col_user_config, idl_seqno)) {
        OVSREC_INTERFACE_FOR_EACH (interface_row, idl) {
            if (OVSREC_IDL_IS_ROW_MODIFIED(interface_row, idl_seqno)) {
                smap_clone(&user_config, &interface_row->user_config);
                admin_status = smap_get(&user_config, INTERFACE_USER_CONFIG_MAP_ADMIN);

                if (admin_status != NULL &&
                    !strcmp(admin_status, OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP)) {
                    int_up = true;
                }

                smap_destroy(&user_config);

                portd_change_if_state(interface_row->name, int_up);
            }
        }
    }

}

/**
 * This function processes the interface "up"/"down" notifications
 * that are received from OVSDB. In response to a change in interface
 * admin state, this function does the following:
 * 1. The functions finds the port structure corresponding to the
 *    interface name whose state has changed. For this we need to
 *    iterate over all the vrfs in our cache and find the port
 *    structure corresponding to the interface name.
 * 2. In event, we find a port structure corresponding to the
 *    interface name and the interface administration state went to
 *    "up", we go ahead and reprogram the IPv6 addresses on that
 *    port.
 */
static void
portd_process_interace_up_down_events(void)
{
    const struct ovsrec_interface *interface_row = NULL;
    struct vrf* vrf;
    struct port* port;

    /*
     * Check if the admin state column changed in this interface
     * change notification.
     */
    if (OVSREC_IDL_IS_COLUMN_MODIFIED(
               ovsrec_interface_col_admin_state, idl_seqno)) {
        /*
         * Iterate through all the interface rows in the interface
         * table.
         */
        OVSREC_INTERFACE_FOR_EACH (interface_row, idl) {

            VLOG_DBG("Got a notification for interface %s "
                     "for admin state %s\n",
                     interface_row->name, interface_row->admin_state);

            /*
             * If the interface row changed due to admin state change,
             * then find the port corresponding to the interface name
             * by iterating over all the ports in a given vrf. We are
             * assuming that port name and the interface name are same.
             */
            if (OVSREC_IDL_IS_ROW_MODIFIED(interface_row, idl_seqno)) {

                VLOG_DBG("Interface %s admin state changed\n",
                         interface_row->name);

                /*
                 * Get the port data structure to reconfigure the IPv6
                 * addresses in order to reconfigure them back into
                 * the kernel.
                 */
                vrf = NULL;
                port = NULL;
                HMAP_FOR_EACH (vrf, node, &all_vrfs) {

                    port = portd_port_lookup(vrf, interface_row->name);

                    /*
                     * If a valid port structure is found, the break.
                     */
                    if (port) {
                        VLOG_DBG("Found the port corresponding "
                                 "to the interface %s\n",
                                 interface_row->name);
                        break;
                    }
                }

                if (port) {

                    /*
                     * If the interface event is administratively forced to,
                     * 'PORT_INTERFACE_ADMIN_UP' reprogram the primary
                     * port address and all the secondary port addresses
                     * on the port. This needs to be done for IPv6 since
                     * the IPv6 addresses get deleted from the kernel when
                     * the kernel interface is administratively forced
                     * 'PORT_INTERFACE_ADMIN_DOWN'.
                     */
                    if (strcmp(interface_row->admin_state,
                               PORT_INTERFACE_ADMIN_UP) == 0) {

                        VLOG_DBG("Reprogramming the IPv6 address again since "
                                 "the interface is forced up again");

                        portd_add_ipv6_addr(port);
                    }
                }
            }
        }
    }
}

/* collect the ports from the current config in db */
static void
portd_collect_wanted_ports(struct vrf *vrf,
                             struct shash *wanted_ports)
{
    size_t i;

    shash_init(wanted_ports);

    for (i = 0; i < vrf->cfg->n_ports; i++) {
        const char *name = vrf->cfg->ports[i]->name;
        shash_add_once(wanted_ports, name, vrf->cfg->ports[i]);
    }
}

/* remove the ports that are in local cache and not in db */
static void
portd_del_ports(struct vrf *vrf, const struct shash *wanted_ports)
{
    struct port *port, *next;

    HMAP_FOR_EACH_SAFE (port, next, port_node, &vrf->ports) {
        port->cfg = shash_find_data(wanted_ports, port->name);
        if (!port->cfg) {
            /* Port not present in the wanted_ports list. Destroy */
            portd_del_internal_vlan(port->internal_vid);
            portd_del_ipaddr(port);
            portd_port_destroy(port);
        }
    }
}

/* create port in cache */
static void
portd_port_create(struct vrf *vrf, struct ovsrec_port *port_row)
{
    struct port *port;

    port = xzalloc(sizeof *port);
    port->vrf = vrf;
    port->name = xstrdup(port_row->name);
    port->cfg = port_row;
    port->internal_vid = -1;
    hmap_init(&port->secondary_ip4addr);
    hmap_init(&port->secondary_ip6addr);

    hmap_insert(&vrf->ports, &port->port_node, hash_string(port->name, 0));

    VLOG_DBG("port '%s' created", port->name);
    return;
}

/* HALON_TODO - update port table status column with error if no VLAN allocated. */
static int
portd_alloc_internal_vlan(void)
{
    int i, ret = -1;
    const struct ovsrec_bridge *br_row = NULL;
    const struct ovsrec_open_vswitch *ovs = NULL;
    struct svec vlans;
    char vlan_name[16];
    int min_internal_vlan, max_internal_vlan;
    const char *internal_vlan_policy;

    ovs = ovsrec_open_vswitch_first(idl);

    if (ovs) {
        min_internal_vlan = smap_get_int(&ovs->other_config,
                     OPEN_VSWITCH_OTHER_CONFIG_MAP_MIN_INTERNAL_VLAN,
                     DFLT_OPEN_VSWITCH_OTHER_CONFIG_MAP_MIN_INTERNAL_VLAN_ID);
        max_internal_vlan = smap_get_int(&ovs->other_config,
                     OPEN_VSWITCH_OTHER_CONFIG_MAP_MAX_INTERNAL_VLAN,
                     DFLT_OPEN_VSWITCH_OTHER_CONFIG_MAP_MAX_INTERNAL_VLAN_ID);
        internal_vlan_policy = smap_get(&ovs->other_config,
                     OPEN_VSWITCH_OTHER_CONFIG_MAP_INTERNAL_VLAN_POLICY);
        if (!internal_vlan_policy) {
            internal_vlan_policy =
                OPEN_VSWITCH_OTHER_CONFIG_MAP_INTERNAL_VLAN_POLICY_ASCENDING_DEFAULT;
        }
        VLOG_DBG("min_internal : %d, %d, %s",
                  min_internal_vlan, max_internal_vlan,
                  internal_vlan_policy);

    } else {
        VLOG_ERR("Unable to acces open_vswitch table in db.");
        return -1;
    }

    OVSREC_BRIDGE_FOR_EACH (br_row, idl) {
        if (!strcmp(br_row->name, DEFAULT_BRIDGE_NAME)) {
            svec_init(&vlans);
            for (i = 0; i < br_row->n_vlans; i++) {
                struct ovsrec_vlan *vlan_row = br_row->vlans[i];
                svec_add(&vlans, vlan_row->name);
            }
            svec_sort(&vlans);
            if (!strcmp(internal_vlan_policy,
                OPEN_VSWITCH_OTHER_CONFIG_MAP_INTERNAL_VLAN_POLICY_ASCENDING_DEFAULT)) {
                int j;
                bool found = false;
                for (j = min_internal_vlan; j <= max_internal_vlan; j++) {
                    snprintf(vlan_name, 16, "VLAN%d", j);
                    if (!svec_contains(&vlans, vlan_name)) {
                        VLOG_DBG("Allocated internal vlan (%d)", j);
                        found = true;
                        ret = j;
                        break;
                    }
                }
                if (!found) {
                    ret = -1;
                }
            } else if (!strcmp(internal_vlan_policy,
                OPEN_VSWITCH_OTHER_CONFIG_MAP_INTERNAL_VLAN_POLICY_DESCENDING)) {
                int j;
                bool found = false;
                for (j = max_internal_vlan; j >= min_internal_vlan; j--) {
                    snprintf(vlan_name, 16, "VLAN%d", j);
                    if (!svec_contains(&vlans, vlan_name)) {
                        VLOG_DBG("Allocated internal vlan (%d)", j);
                        found = true;
                        ret = j;
                        break;
                    }
                }
                if (!found) {
                    ret = -1;
                }
            } else {
                VLOG_ERR("Unknown internal vlan policy '%s'",
                          internal_vlan_policy);
                ret = -1;
            }
            svec_destroy(&vlans);
            break; /* do this only on bridge_normal */
        }
    }
    return ret;
}

/* add new vlan row into db */
static void
portd_bridge_insert_vlan(struct ovsrec_bridge *br, struct ovsrec_vlan *vlan)
{
    struct ovsrec_vlan **vlans;
    size_t i;

    vlans = xmalloc(sizeof *br->vlans * (br->n_vlans + 1));
    for (i = 0; i < br->n_vlans; i++) {
        vlans[i] = br->vlans[i];
    }
    vlans[br->n_vlans] = vlan;
    ovsrec_bridge_set_vlans(br, vlans, br->n_vlans + 1);
    commit_txn = true;
    free(vlans);
}

/* create a new internal vlan row to be inserted into db */
static void
portd_create_vlan_row(int vid, struct ovsrec_port *port_row)
{
    char vlan_name[16];
    struct smap vlan_internal_smap;
    const struct ovsrec_bridge *br_row = NULL;
    struct ovsrec_vlan *vlan = NULL;

    vlan = ovsrec_vlan_insert(txn);
    snprintf(vlan_name, 16, "VLAN%d", vid);
    ovsrec_vlan_set_name(vlan, vlan_name);
    ovsrec_vlan_set_id(vlan, vid);
    ovsrec_vlan_set_admin(vlan, OVSREC_VLAN_ADMIN_UP);
    ovsrec_vlan_set_oper_state(vlan, OVSREC_VLAN_OPER_STATE_UP);
    ovsrec_vlan_set_oper_state_reason(vlan, OVSREC_VLAN_OPER_STATE_REASON_OK);

    /* update VLAN table "internal_usage" with the L3 port name */
    smap_init(&vlan_internal_smap);
    smap_add(&vlan_internal_smap, VLAN_INTERNAL_USAGE_L3PORT, port_row->name);
    ovsrec_vlan_set_internal_usage(vlan, &vlan_internal_smap);
    commit_txn = true;
    smap_destroy(&vlan_internal_smap);

    OVSREC_BRIDGE_FOR_EACH (br_row, idl) {
        if (!strcmp(br_row->name, DEFAULT_BRIDGE_NAME)) {
            VLOG_DBG("Creating VLAN row '%s'", vlan_name);
            portd_bridge_insert_vlan((struct ovsrec_bridge *)br_row, vlan);
        }
    }
}

/* HALON_TODO - move internal_vlan functions to a separate file */
static void
portd_add_internal_vlan(struct port *port, struct ovsrec_port *port_row)
{
    int vid;
    char vlan_id[16];
    int require_vlan;
    struct smap hw_cfg_smap;
    const struct ovsrec_subsystem *ovs_subsys;

    /* HALON_TODO: handle multiple subsystems. */
    ovs_subsys = ovsrec_subsystem_first(idl);

    if (ovs_subsys) {
        require_vlan = smap_get_int(&ovs_subsys->other_info,
                                    "l3_port_requires_internal_vlan",
                                    0);
        VLOG_DBG("l3_port requires vlan : %d", require_vlan);
        if (require_vlan == 0) {
            return;
        }
    } else {
        VLOG_ERR("Unable to acces subsystem table in db.");
        return;
    }

    vid = portd_alloc_internal_vlan();
    if (vid == -1) {
        VLOG_ERR("Error allocating internal vlan for port '%s'", port_row->name);
        return;
    }

    portd_create_vlan_row(vid, port_row);

    /* update port table "hw_config" with the generated vlan id */
    smap_init(&hw_cfg_smap);
    snprintf(vlan_id, 16, "%d", vid);
    smap_add(&hw_cfg_smap, PORT_HW_CONFIG_MAP_INTERNAL_VLAN_ID, vlan_id);
    ovsrec_port_set_hw_config(port_row, &hw_cfg_smap);
    commit_txn = true;
    smap_destroy(&hw_cfg_smap);

    port->internal_vid = vid;

    return;

}

static void
portd_reconfig_ports(struct vrf *vrf, const struct shash *wanted_ports)
{
    struct shash_node *port_node;

    SHASH_FOR_EACH (port_node, wanted_ports) {
        struct ovsrec_port *port_row = port_node->data;
        struct port *port = portd_port_lookup(vrf, port_row->name);
        if (!port) {

            VLOG_DBG("Creating new port %s vrf %s\n",port_row->name, vrf->name);
            portd_port_create(vrf, port_row);
            port = portd_port_lookup(vrf, port_row->name);

            portd_add_internal_vlan(port, port_row);

            portd_reconfig_ipaddr(port, port_row);
            VLOG_DBG("Port has IP: %s vrf %s\n", port_row->ip4_address,
                      vrf->name);
        } else if ((port) && OVSREC_IDL_IS_ROW_MODIFIED(port_row, idl_seqno)) {
            portd_reconfig_ipaddr(port, port_row);
            /* Port table row modified */
            VLOG_DBG("Port modified IP: %s vrf %s\n", port_row->ip4_address,
                     vrf->name);
        }
    }
}

static void
portd_add_del_ports(void)
{
    struct vrf *vrf;

    /* For each vrf in all_vrfs, update the port list */
    HMAP_FOR_EACH (vrf, node, &all_vrfs) {
        VLOG_DBG("in vrf %s to delete ports\n",vrf->name);
        portd_collect_wanted_ports(vrf, &vrf->wanted_ports);
        portd_del_ports(vrf, &vrf->wanted_ports);
    }
    /* For each vrfs' port list, configure them */
    HMAP_FOR_EACH (vrf, node, &all_vrfs) {
        VLOG_DBG("in vrf %s to reconfigure ports\n",vrf->name);
        portd_reconfig_ports(vrf, &vrf->wanted_ports);
        shash_destroy(&vrf->wanted_ports);
    }
}

/* Checks to see if:
 * vrf has been added/deleted.
 * port has been added/deleted from a vrf.
 * port has been modified (IP address(es)).
 */
static void
portd_reconfigure(void)
{
    unsigned int new_idl_seqno = ovsdb_idl_get_seqno(idl);

    VLOG_DBG("Received a OVSDB change notification "
             "with current idl as %u and new idl as %u\n",
             idl_seqno, new_idl_seqno);

    if (new_idl_seqno == idl_seqno){
        return;
    }

    portd_add_del_vrf();
    portd_add_del_ports();
    portd_process_interace_up_down_events();
    portd_process_interface_admin_up_down_events();

    idl_seqno = new_idl_seqno; /* This has to be done after all changes are done */
    return;
}

static void
portd_run(void)
{

    ovsdb_idl_run(idl);

    if (ovsdb_idl_is_lock_contended(idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&rl, "another halon-portd process is running, "
                    "disabling this process until it goes away");

        return;
    } else if (!ovsdb_idl_has_lock(idl)) {
        return;
    }

    portd_chk_for_system_configured();
    if (!system_configured) {
        return;
    }

    commit_txn = false; /* if db was modified, this flag gets set */
    txn = ovsdb_idl_txn_create(idl);
    portd_reconfigure();
    if (commit_txn) {
        ovsdb_idl_txn_commit_block(txn);
    }
    ovsdb_idl_txn_destroy(txn);
    VLOG_INFO_ONCE("%s (Halon portd) %s", program_name, VERSION);

    /* HALON_TODO - verify db write was successful, else retry. */
    /* HALON_TODO - restartability of portd, ovsdb */
    /* HALON_TODO - cur_cfg delete once after system init */
}

static void
portd_wait(void)
{
    ovsdb_idl_wait(idl);
    poll_timer_wait(PORTD_POLL_INTERVAL * 1000);
}

static void
portd_unixctl_dump(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    unixctl_command_reply_error(conn, "Nothing to dump :)");
}

static void
usage(void)
{
    printf("%s: Halon portd daemon\n"
            "usage: %s [OPTIONS] [DATABASE]\n"
            "where DATABASE is a socket on which ovsdb-server is listening\n"
            "      (default: \"unix:%s/db.sock\").\n",
            program_name, program_name, ovs_rundir());
    stream_usage("DATABASE", true, false, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
            "  --unixctl=SOCKET        override default control socket name\n"
            "  -h, --help              display this help message\n"
            "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

static char *
parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_UNIXCTL = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
    };

    static const struct option long_options[] = {
            {"help",        no_argument, NULL, 'h'},
            {"version",     no_argument, NULL, 'V'},
            {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
            DAEMON_LONG_OPTIONS,
            VLOG_LONG_OPTIONS,
            {NULL, 0, NULL, 0},
    };

    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(OFP10_VERSION, OFP10_VERSION);
            exit(EXIT_SUCCESS);

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

            VLOG_OPTION_HANDLERS
            DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {
    case 0:
        return xasprintf("unix:%s/db.sock", ovs_rundir());

    case 1:
        return xstrdup(argv[0]);

    default:
        VLOG_FATAL("at most one non-option argument accepted; "
                "use --help for usage");
    }
}

static void
halon_portd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
        const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

int
main(int argc, char *argv[])
{
    char *unixctl_path = NULL;
    struct unixctl_server *unixctl;
    char *remote;
    bool exiting;
    int retval;

    set_program_name(argv[0]);
    proctitle_init(argc, argv);
    remote = parse_options(argc, argv, &unixctl_path);
    fatal_ignore_sigpipe();

    ovsrec_init();

    daemonize_start();

    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, halon_portd_exit, &exiting);

    portd_init(remote);
    free(remote);
    daemonize_complete();
    vlog_enable_async();

    exiting = false;
    while (!exiting) {
        portd_run();
        unixctl_server_run(unixctl);

        portd_wait();
        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        } else {
            poll_block();
        }
    }
    portd_exit();
    unixctl_server_destroy(unixctl);

    return 0;
}
