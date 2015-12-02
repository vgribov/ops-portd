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
 *
 */

/* This daemon handles the following functionality:
 * - Allocating internal VLAN for L3 interface.
 * - Configuring IP address for L3 interface.
 * - Enable/disable IP routing
 * - Add/delete intervlan interfaces
 */

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* OVSDB Includes */
#include "config.h"
#include "command-line.h"
#include "coverage.h"
#include "daemon.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "openswitch-dflt.h"
#include "poll-loop.h"
#include "stream.h"
#include "unixctl.h"
#include "vlan-bitmap.h"

#include "portd.h"

VLOG_DEFINE_THIS_MODULE(ops_portd);

COVERAGE_DEFINE(portd_reconfigure);

int nl_sock; /* Netlink socket */
int init_sock; /* This sock will only be used during init */

/* IDL variables */
unsigned int idl_seqno;
struct ovsdb_idl *idl;
struct ovsdb_idl_txn *txn;

bool commit_txn = false;

static unixctl_cb_func portd_unixctl_dump;
static int system_configured = false;

/* This static boolean is used to configure VLANs
 * and sync IP addresses on initialization
 * and to handle restarts. */
static bool portd_config_on_init = true;

/* All vrfs, indexed by name. */
struct hmap all_vrfs = HMAP_INITIALIZER(&all_vrfs);

/* Utility functions */
static struct vrf* portd_vrf_lookup(const char *name);
static struct port* portd_port_lookup(const struct vrf *vrf,
                                      const char *name);
static bool portd_check_interface_type_vlan(struct rtattr *link_info,
                                            int len);
static inline void portd_chk_for_system_configured(void);

/* Netlink related functions */
static void portd_vlan_intf_config_on_init(int intf_index,
                                           struct rtattr *link_info);
static void portd_update_kernel_intf_up_down (char *intf_name);
static void parse_nl_new_link_msg(struct nlmsghdr *h);
static void portd_netlink_socket_open(int *sock, bool is_init_sock);

static void portd_init(const char *remote);
static void portd_exit(void);
static void portd_set_status_error(const struct ovsrec_port *port_row,
                                   char *error);
static void portd_set_hw_cfg(struct port *port,
                             const struct ovsrec_port *port_row);
static void portd_interface_up_down(const char *interface_name,
                                    const char *status);
static void portd_set_interface_mtu(const char *interface_name,
                                    unsigned int mtu);
static struct ovsrec_interface* portd_get_matching_interface_row(
        const struct ovsrec_port *portrow);
static struct ovsrec_port* portd_get_port_row(
        const struct ovsrec_interface *intf_row);
static void portd_port_admin_state_reconfigure(
        struct port *port, const struct ovsrec_port *port_row);
static void portd_handle_interface_config_mods(void);

/* Internal VLAN related functions */
static void portd_bridge_del_vlan(struct ovsrec_bridge *br,
                                  struct ovsrec_vlan *vlan);
static void portd_del_internal_vlan(int internal_vid);
static int portd_alloc_internal_vlan(void);
static void portd_bridge_insert_vlan(struct ovsrec_bridge *br,
                                     struct ovsrec_vlan *vlan);
static void portd_create_vlan_row(int vid, struct ovsrec_port *port_row);
static void portd_add_internal_vlan(struct port *port,
                                    struct ovsrec_port *port_row);

/* Port related functions */
static void portd_port_create(struct vrf *vrf,
                              struct ovsrec_port *port_row);
static void portd_reconfig_ports(struct vrf *vrf,
                                 const struct shash *wanted_ports);
static void portd_collect_wanted_ports(struct vrf *vrf,
                                       struct shash *wanted_ports);
static void portd_port_destroy(struct port *port);
static void portd_del_ports(struct vrf *vrf,
                            const struct shash *wanted_ports);
static void portd_add_del_ports(void);

/* Init functions */
static void portd_intf_config_on_init (void);
static void portd_vlan_config_on_init(void);

/* VRF related functions */
static void portd_vrf_del(struct vrf *vrf);
static void portd_vrf_add(const struct ovsrec_vrf *vrf_row);
static void portd_add_del_vrf(void);

static void portd_reconfigure(void);
static void portd_service_netlink_messages(void);
static void portd_run(void);
static void portd_netlink_recv_wait__(void);
static void portd_wait(void);
static void portd_unixctl_dump(struct unixctl_conn *conn,
                               int argc OVS_UNUSED,
                               const char *argv[] OVS_UNUSED,
                               void *aux OVS_UNUSED);
static char * parse_options(int argc, char *argv[], char **unixctl_pathp);
static void ops_portd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                           const char *argv[] OVS_UNUSED, void *exiting_);

/*
 * Lookup port entry from DB
 */
struct ovsrec_port*
portd_port_db_lookup(const char *name)
{
    const struct ovsrec_port *port_row;

    OVSREC_PORT_FOR_EACH(port_row, idl) {
        if (!strcmp(port_row->name, name)) {
            struct ovsrec_port *temp_port_row =
                    CONST_CAST(struct ovsrec_port *, port_row);
            return temp_port_row;
        }
    }
    return NULL;
}

/**
 * Function: portd_interface_type_internal_check
 * Param:
 *      port: port record whose interfaces are examined for "internal" type.
 *      interface_name: Name of interface to check "internal" type.
 * Return:
 *      true  : Provided interface exists and is of type "internal"
 *      false : Provide interface either doesn't exist or not "internal" type.
 */
bool
portd_interface_type_internal_check(const struct ovsrec_port *port,
                                    const char *interface_name)
{
    struct ovsrec_interface *intf;
    size_t i = 0;

    for (i = 0; i < port->n_interfaces; ++i) {
        intf = port->interfaces[i];
        if (strcmp(port->name, intf->name) == 0 &&
            strcmp(intf->type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0) {

            VLOG_DBG("[%s:%d]: Interface %s is of type \"internal\" found. ",
                        __FUNCTION__, __LINE__, interface_name);
            return true;
        }
    }

    VLOG_DBG("[%s:%d]: Interface %s is NOT of type \"internal\". ",
                __FUNCTION__, __LINE__, interface_name);
    return false;
}

/**
 * Function: portd_port_in_bridge_check
 * Param:
 *      port_name: Name of port that is examined in bridge normal record.
 *      bridge_name: Name of bridge to be examined. If NULL/Empty, check all
 *                   bridge records.
 * Return:
 *      true  : Provided port is present in "bridge_normal"
 *      false : Provide port is not in "bridge_normal"
 */
bool
portd_port_in_bridge_check(const char *port_name, const char *bridge_name)
{
    const struct ovsrec_bridge *row, *next;
    struct ovsrec_port  *port;
    size_t i;

    OVSREC_BRIDGE_FOR_EACH_SAFE (row, next, idl) {
        if (bridge_name &&
            (strcmp(bridge_name, PORTD_EMPTY_STRING) != 0) &&
            (strcmp(row->name, bridge_name) != 0)) {
            continue;
        }

        for (i = 0; i < row->n_ports; i++) {
            port = row->ports[i];
            /* input port is part of one of bridge */
            if (strcmp(port->name, port_name) == 0) {
                VLOG_DBG("[%s:%d]: Port %s is part of bridge %s", __FUNCTION__,
                                __LINE__, port_name, bridge_name);
                return true;
            }
        }
    }

    VLOG_DBG("[%s:%d]: Port %s is NOT found in bridge %s", __FUNCTION__,
            __LINE__, port_name, bridge_name);

    return false;
}

/**
 * Function: portd_port_in_vrf_check
 * Param:
 *      port_name: Name of port that is examined in default VRF record.
 *      vrf_name: Name of VRF to be examined. NULL/empty string means, search
 *                ALL VRF records.
 * Return:
 *      true  : Provided port is present in default VRF
 *      false : Provide port is not in default VRF
 */
bool
portd_port_in_vrf_check(const char *port_name, const char *vrf_name)
{
    const struct ovsrec_vrf *row, *next;
    struct ovsrec_port  *port;
    size_t  i;

    OVSREC_VRF_FOR_EACH_SAFE (row, next, idl) {
        if (vrf_name &&
            (strcmp(vrf_name, PORTD_EMPTY_STRING) != 0) &&
            (strcmp(row->name, vrf_name) != 0)) {
            continue;
        }

        for (i = 0; i < row->n_ports; i++) {
            port = row->ports[i];
            /* input port is part of one of bridge */
            if (strcmp(port->name, port_name) == 0) {
                VLOG_DBG("[%s:%d]: Port %s is part of VRF %s", __FUNCTION__,
                                __LINE__, port_name, vrf_name);
                return true;
            }
        }
    }

    VLOG_DBG("[%s:%d]: Port %s is NOT found in VRF %s", __FUNCTION__,
            __LINE__, port_name, vrf_name);

    return false;
}

/*
 * This function is used to parse the dump command response.
 * It handles multi part message and calls the parse_nl_msg
 * function to act on Netlink messages.
 * The on_init flag is used to ensure that the recvmsg
 * blocks when init socket is reading the dump responses.
 */
void
nl_msg_process(void *user_data, int sock, bool on_init)
{
    bool multipart_msg_end = false;

    while (!multipart_msg_end) {
        struct sockaddr_nl nladdr;
        struct msghdr msg;
        struct iovec iov;
        struct nlmsghdr *nlh;
        char buffer[RECV_BUFFER_SIZE];
        int ret;

        iov.iov_base = (void *)buffer;
        iov.iov_len = sizeof(buffer);
        msg.msg_name = (void *)&(nladdr);
        msg.msg_namelen = sizeof(nladdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        /* In order not to block on the recvmsg, MSG_DONTWAIT
         * is passed as a flag. the return value is EAGAIN if
         * no data is available
         * MSG_DONTWAIT is used during normal flow.
         * On init, we will block till we get updates from
         * the kernel and perform reconfiguration of
         * IP addresses and interfaces
         */
        ret = recvmsg(sock, &msg, on_init ? 0 : MSG_DONTWAIT);

        if (ret < 0) {
            return;
        }

        nlh = (struct nlmsghdr*) buffer;

        for (nlh = (struct nlmsghdr *) buffer;
             NLMSG_OK(nlh, ret);
             nlh = NLMSG_NEXT(nlh, ret)) {
            switch(nlh->nlmsg_type) {

            case RTM_NEWADDR:
                /*
                 * The network address dump request is only made
                 * during init. The assumption is that all the
                 * address messages from the kernel comes back
                 * immediately. So, check on the portd_config_on_init
                 * flag before we process address messages from kernel
                 */
                if (portd_config_on_init) {
                    parse_nl_ip_address_msg_on_init(nlh, ret, user_data);
                }
                break;
            case RTM_NEWLINK:
                parse_nl_new_link_msg(nlh);
                break;

            case NLMSG_DONE:
                VLOG_DBG("End of multi part message");
                multipart_msg_end = true;
                break;

            default:
                break;
            } /* end of switch */

            if (!(nlh->nlmsg_flags & NLM_F_MULTI)) {
                VLOG_DBG("End of message. Not a multipart message");
                goto end;
            }
        }
    }
end:
    return;
}

/**
 * Identify which 'vrf' a 'port' belongs to and return
 * the corresponding vrf or NULL if not found
 */
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

/*
 * Parse the nested rtattr in IFLA_LINKFO and check if the interface
 * is of type 'vlan'
 */
static bool
portd_check_interface_type_vlan(struct rtattr *link_info, int len)
{
    while ((RTA_OK(link_info, len)) &&
           (link_info->rta_type <= IFLA_INFO_MAX)) {
            /* Check for Interface type 'vlan' */
            if ((link_info->rta_type == IFLA_INFO_KIND) &&
                (strcmp(RTA_DATA(link_info), INTERFACE_TYPE_VLAN) == 0)) {
            return true;
        }
        link_info = RTA_NEXT(link_info, len);
    }
    return false;
}

static inline void
portd_chk_for_system_configured(void)
{
    const struct ovsrec_system *ovs_vsw = NULL;

    if (system_configured) {
        /* Nothing to do if we're already configured. */
        return;
    }

    ovs_vsw = ovsrec_system_first(idl);

    if (ovs_vsw && (ovs_vsw->cur_cfg > (int64_t) 0)) {
        system_configured = true;
        VLOG_DBG("System is now configured (cur_cfg=%d).",
                (int)ovs_vsw->cur_cfg);
    }

}

/*
 * Fetch the OVSDB port row for VLAN
 * and delete from kernel if not present in DB
 */
static void
portd_vlan_intf_config_on_init(int intf_index, struct rtattr *link_info)
{
    struct ovsrec_port *port_row;
    char ifname[IF_NAMESIZE];

    if (!portd_check_interface_type_vlan(RTA_DATA(link_info),
                                         RTA_PAYLOAD(link_info))) {
        /* Interface is not of type 'vlan' */
        return;
    }

    memset(ifname, 0, sizeof(ifname));
    if_indextoname(intf_index, ifname);

    port_row = portd_port_db_lookup(ifname);
    /*
     * Check if vlan interface entry was present in DB.
     * If not, remove the vlan interface from the kernel.
     */
    if (!port_row ||
        !(portd_interface_type_internal_check(port_row, port_row->name) &&
          portd_port_in_bridge_check(port_row->name, DEFAULT_BRIDGE_NAME) &&
          portd_port_in_vrf_check(port_row->name, DEFAULT_VRF_NAME))) {
        VLOG_DBG("Deleting VLAN Interface %s", ifname);
        portd_del_vlan_interface(ifname);
    }
}

/*
 * Fetch the OVSDB interface row and update the kernel with
 * admin up/down messages
 */
static void
portd_update_kernel_intf_up_down(char *intf_name)
{
    const struct ovsrec_interface *interface_row = NULL;
    struct smap user_config;
    const char *admin_status;

    OVSREC_INTERFACE_FOR_EACH (interface_row, idl) {
        if (!strcmp(intf_name, interface_row->name)) {
            smap_clone(&user_config, &interface_row->user_config);
            admin_status = smap_get(&user_config,
                                    INTERFACE_USER_CONFIG_MAP_ADMIN);

            if (admin_status != NULL &&
                !strcmp(admin_status,
                        OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP)) {
                portd_interface_up_down(interface_row->name,
                                        OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP);
            } else {
                portd_interface_up_down(interface_row->name,
                                        OVSREC_INTERFACE_USER_CONFIG_ADMIN_DOWN);
            }
            smap_destroy(&user_config);
        }
    }
}

/*
 * Parse the netlink message to read all the attributes of a
 * new link message. On reading IFLA_IFNAME, verify the interface
 * state from the DB and update the kernel accordingly.
 */
static void
parse_nl_new_link_msg(struct nlmsghdr *h)
{
    struct ifinfomsg *iface;
    struct rtattr *attribute;
    int len;

    iface = NLMSG_DATA(h);
    len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

    for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len);
         attribute = RTA_NEXT(attribute, len)) {
        switch(attribute->rta_type) {
        case IFLA_IFNAME:
            VLOG_DBG("New interface %d : %s\n",
                     iface->ifi_index, (char *) RTA_DATA(attribute));
            portd_update_kernel_intf_up_down((char *)RTA_DATA(attribute));
            break;
        case IFLA_LINKINFO:
            /*
             * This case is especially used for processing
             * intervlan interfaces. They are processed only during init.
             */
            if (portd_config_on_init) {
                portd_vlan_intf_config_on_init(iface->ifi_index, attribute);
            }
            break;
        default:
            break;
        }
    }
}

/*
 * Creates a netlink socket. We currently use two sockets:
 * 1. nl_sock   : To listen for udpates from the kernel
 * 2. init_sock : To send IP address & interface dump requests
 *                and perform reconfiguration on init.
 */
static void
portd_netlink_socket_open(int *sock, bool is_init_sock)
{
    struct sockaddr_nl s_addr;

    *sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (*sock < 0) {
        VLOG_ERR("Netlink socket creation failed (%s)",strerror(errno));
        return;
    }

    memset((void *) &s_addr, 0, sizeof(s_addr));
    s_addr.nl_family = AF_NETLINK;
    if (!is_init_sock) {
        s_addr.nl_pid = getpid();
        s_addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_LINK;
    }
    if (bind(*sock, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
        VLOG_ERR("Netlink socket bind failed (%s)",strerror(errno));
        return;
    }

    VLOG_DBG("Netlink socket created. fd = %d",*sock);
    return;
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
    ovsdb_idl_set_lock(idl, "ops_portd");
    ovsdb_idl_verify_write_only(idl);

    ovsdb_idl_add_table(idl, &ovsrec_table_subsystem);
    ovsdb_idl_add_column(idl, &ovsrec_subsystem_col_other_info);

    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_cur_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_other_config);

    ovsdb_idl_add_table(idl, &ovsrec_table_vrf);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_vrf_col_ports);

    ovsdb_idl_add_table(idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_vlans);
    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_vlans);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_hw_config);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_hw_config);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_ip4_address);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_ip4_address_secondary);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_ip6_address);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_ip6_address_secondary);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_tag);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_admin);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_status);
    /*
     * Adding the interface table so that we can listen to interface
     * "up"/"down" notifications. We need to add two columns to the
     * interface table:-
     * 1. Interface name for finding which port corresponding to the
     *    interface went "up"/"down".
     * 2. Interface admin state.
     * 3. Interface type. If it's "internal", then create a VLAN interface in
     *    kernel.
     */
    ovsdb_idl_add_table(idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_admin_state);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_user_config);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_hw_intf_config);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_type);

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

    /*
     * Open a netlink socket for communication with the kernel
     */
    portd_netlink_socket_open(&nl_sock, false);

    /* By default, we disable routing at the start.
     * Enabling will be done as part of reconfigure. */
    portd_config_iprouting(PORTD_DISABLE_ROUTING);
}

static void
portd_exit(void)
{
    close(nl_sock);
    ovsdb_idl_destroy(idl);
}

/* Functin to add status to port table ie up or no_internal_vlan */
static void
portd_set_status_error(const struct ovsrec_port *port_row, char *error)
{
    struct smap set_status_smap;
    if(!port_row){
        VLOG_ERR("Invalid call with port entry null");
        return;
    }
    smap_init(&set_status_smap);
    smap_clone(&set_status_smap, &port_row->status);
    smap_replace(&set_status_smap, PORT_STATUS_MAP_ERROR, error);
    ovsrec_port_set_status(port_row, &set_status_smap);
    smap_destroy(&set_status_smap);
    commit_txn = true;
}

/* Function to set hw_cfg in port row */
static void
portd_set_hw_cfg(struct port *port, const struct ovsrec_port *port_row)
{
    char vlan_id[PORTD_VLAN_ID_STRING_MAX_LEN];
    struct smap hw_cfg_smap;

    if(!port || !port_row) {
        VLOG_ERR("Invalid call with port entry null");
        return;
    }

    VLOG_DBG("Port %s  hw_config:intenal_vlan_id = %d, "
             "hw_config:enable = %d", port->name,
             port->internal_vid, port->hw_cfg_enable);

    smap_init(&hw_cfg_smap);
    smap_clone(&hw_cfg_smap, &port_row->hw_config);

    if (port->internal_vid > 0) {
        /* update port table "hw_config" with the generated vlan id */
        snprintf(vlan_id, PORTD_VLAN_ID_STRING_MAX_LEN,
                 "%d", port->internal_vid);
        smap_replace(&hw_cfg_smap, PORT_HW_CONFIG_MAP_INTERNAL_VLAN_ID,
                     vlan_id);
    } else {
        /*
         * Uninitialized VLAN ID, so we will clear this attribute
         * Internal vlan id are not generated only for L3 interfaces
         * For other ports such as Vlan interfaces we dont need this.
         */
        smap_remove(&hw_cfg_smap, PORT_HW_CONFIG_MAP_INTERNAL_VLAN_ID);
    }

    /* update enable/disable in hw_cfg */
    smap_replace(&hw_cfg_smap, PORT_HW_CONFIG_MAP_ENABLE,
                 port->hw_cfg_enable ?"true":"false");

    ovsrec_port_set_hw_config(port_row, &hw_cfg_smap);

    smap_destroy(&hw_cfg_smap);
    commit_txn = true;
}

/*
 * Function: portd_set_interface_mtu
 * Param:
 *      interface_name: Name of the interface.
 *      mtu : MTU configured for the interface.
 * Return:
 * Desc:
 *      Set MTU value for the interface specified.
 */
static void
portd_set_interface_mtu(const char *interface_name, unsigned int mtu)
{
    struct rtattr *rta;
    struct rtareq req;

    if (interface_name == NULL ||
            strcmp(interface_name, PORTD_EMPTY_STRING) == 0) {
        VLOG_ERR("Invalid interface-name as argument");
        return;
    }
    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len     = NLMSG_SPACE(sizeof(struct ifinfomsg));
    req.n.nlmsg_pid     = getpid();
    req.n.nlmsg_type    = RTM_NEWLINK;
    req.n.nlmsg_flags   = NLM_F_REQUEST;

    req.i.ifi_family    = AF_UNSPEC;
    req.i.ifi_index     = if_nametoindex(interface_name);

    if (req.i.ifi_index == 0) {
        VLOG_ERR("Unable to get ifindex for interface: %s", interface_name);
        return;
    }

    req.i.ifi_change = 0xffffffff;
    rta = (struct rtattr *)(((char *) &req) + NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_type = IFLA_MTU;
    rta->rta_len = RTA_LENGTH(sizeof(unsigned int));
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_LENGTH(sizeof(mtu));
    memcpy(RTA_DATA(rta), &mtu, sizeof(mtu));

    if (send(nl_sock, &req, req.n.nlmsg_len, 0) == -1) {
        VLOG_ERR("Netlink failed to set mtu %d for interface %s", mtu,
                 interface_name);
        return;
    }
}

/**
 * Function: portd_interface_up_down
 * Param:
 *      vlan_interface_name: Name of the interface to be set to "up" or "down".
 *      status: "up" or "down".
 * Return:
 * Desc:
 *      Set an interface state to "up" or "down".
 * FIXME:
 *      Plugin to "shutdown"/"no shutdown" commands under an interface.
 */
static void
portd_interface_up_down(const char *interface_name, const char *status)
{
    struct rtareq req;

    if (status == NULL || strcmp(status, PORTD_EMPTY_STRING) == 0) {
        VLOG_ERR("Invalid status argument");
        return;
    }

    if (interface_name == NULL ||
            strcmp(interface_name, PORTD_EMPTY_STRING) == 0) {
        VLOG_ERR("Invalid interface-name as argument");
        return;
    }

    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len = NLMSG_SPACE(sizeof(struct ifinfomsg));
    req.n.nlmsg_pid     = getpid();
    req.n.nlmsg_type    = RTM_NEWLINK;
    req.n.nlmsg_flags   = NLM_F_REQUEST;

    req.i.ifi_family    = AF_UNSPEC;
    req.i.ifi_index     = if_nametoindex(interface_name);

    if (req.i.ifi_index == 0) {
        VLOG_ERR("Unable to get ifindex for interface: %s", interface_name);
        return;
    }

    /* FIXME: _May_ have to convert this to "no shutdown"/"shutdown" */
    if (strcmp(status, "up") == 0) {
        req.i.ifi_change |= IFF_UP;
        req.i.ifi_flags  |= IFF_UP;
    } else if (strcmp(status, "down") == 0) {
        req.i.ifi_change |= IFF_UP;
        req.i.ifi_flags  &= ~IFF_UP;
    }

    if (send(nl_sock, &req, req.n.nlmsg_len, 0) == -1) {
        VLOG_ERR("Netlink failed to bring %s the interface %s", status,
                 interface_name);
        return;
    }
}

/* Function : portd_get_matching_interface_row()
 * Desc     : search the ovsdb and get the matching
 *            interface row based on the port row name.
 * Param    : seach based on row name
 * Return   : returns the matching row or NULL incase
 *            no row is found.
 */
static struct ovsrec_interface *
portd_get_matching_interface_row(const struct ovsrec_port *port_row)
{
    const struct ovsrec_interface *int_row = NULL;
    int i;

    for (i = 0; i < port_row->n_interfaces; i++) {
        int_row = port_row->interfaces[i];
        if (!strcmp(int_row->name, port_row->name)) {
            return (struct ovsrec_interface *)int_row;
        }
    }
    return NULL;
}

/* Function : portd_get_port_row()
 * Desc     : search the ovsdb and get the port
 *           row for the interface.
 * Param    : interface row
 * Return   : returns the port row or NULL in case
 *            no row is found.
 */
static struct ovsrec_port *
portd_get_port_row(const struct ovsrec_interface *intf_row)
{
    const struct ovsrec_port *port_row = NULL;
    int i;

    /* find out which port has this interface associated with it */
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        if (port_row->n_interfaces) {
            for (i = 0; i < port_row->n_interfaces; i++) {
                if (port_row->interfaces[i] == intf_row) {
                    return (struct ovsrec_port *)port_row;
                }
            }
        }
    }

    return NULL;
}

/* Function : portd_port_admin_state_reconfigure()
 * Desc     : Updates the hw_config key "enable" based on the user
 *            configuration to set the port admin state to up or down.
 * Param    : None
 * Return   : None
 */
static void
portd_port_admin_state_reconfigure(struct port *port,
                                   const struct ovsrec_port *port_row)
{
    const struct ovsrec_interface *intf_row = NULL;
    char *cur_state = NULL;
    /* default states of interface and port admin */
    bool intf_admin = false;
    bool port_admin = true;

    /*
     * Check if the admin state column changed.
     */
    if ((OVSREC_IDL_IS_COLUMN_MODIFIED(
                ovsrec_port_col_admin, idl_seqno)) ||
        (OVSREC_IDL_IS_COLUMN_MODIFIED(
                ovsrec_port_col_interfaces, idl_seqno))) {

        VLOG_DBG("port column modified\n");

            /* If the port row is modified then
             * update the hw_config for that row */
            if (OVSREC_IDL_IS_ROW_MODIFIED(port_row, idl_seqno)) {
                /* Check for port admin changes based on interface
                   row user_config chnages */
                if ((intf_row = portd_get_matching_interface_row(port_row))
                        != NULL) {
                    /* Its a VLAN or L3 interface */
                    VLOG_DBG("set up state for L3 and vlan interface\n");
                    /* Get interface state */
                    cur_state = (char *)smap_get(&intf_row->user_config,
                                                 INTERFACE_USER_CONFIG_MAP_ADMIN);
                    if (cur_state &&
                        (VTYSH_STR_EQ(cur_state,
                                      OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP))) {
                        intf_admin = true;
                    }
                    /* Get port state */
                    if (port_row->admin &&
                        (VTYSH_STR_EQ(port_row->admin,
                                      PORT_CONFIG_ADMIN_DOWN))) {
                        port_admin = false;
                    }
                    /* The final state is the 'and operation' between
                       the port admin and the interface admin */
                    port->hw_cfg_enable = (intf_admin && port_admin);
                } else {
                    /* its a LAG */
                    /* set hw_config same as port admin_status */
                    VLOG_DBG("set up in LAG interface\n");
                    if ((port_row->admin == NULL) ||
                        (strcmp(port_row->admin, "up") == 0)) {
                        port->hw_cfg_enable = true;
                    } else {
                        port->hw_cfg_enable = false;
                    }
                }
                portd_set_hw_cfg(port, port_row);
            }
    }
}

/**
 * This function processes the interface "up"/"down" notifications
 * & MTU notifications that are received from OVSDB.
 * In response to a change in interface
 * admin state, this function does the following:
 * 1. Based on interface user_config:admin, bring up/down the kernel
 *    interface
 * 2. The functions finds the port structure corresponding to the
 *    interface name whose state has changed. For this we need to
 *    iterate over all the vrfs in our cache and find the port
 *    structure corresponding to the interface name.
 * 3. In event, we find a port structure corresponding to the
 *    interface name and the interface administration state went to
 *    "up", we go ahead and reprogram the IPv6 addresses on that
 *    port.
 * 4. If port found, updates the hw_config key "enable" based on the user
 *            configuration to set the port admin state to up or down.
 * In response to change in MTU value in hw_config_info,
 * 1. Finds the port structure corresponding to the interface name and
 *    updates the MTU value for that kernel interface.
 */
static void
portd_handle_interface_config_mods(void)
{
    const struct ovsrec_port *port_row = NULL;
    const struct ovsrec_interface *intf_row = NULL;
    char *cur_state = NULL;
    char *hw_intf_config_mtu = NULL;

    /* default states of interface and port admin */
    bool intf_admin = false;
    bool port_admin = true;
    struct port *port = NULL;
    struct vrf *vrf;

    VLOG_DBG("portd_intf_admin_state_up_down_events\n");

    VLOG_INFO("Interface user config column modified\n");
    OVSREC_INTERFACE_FOR_EACH (intf_row, idl) {
        port = NULL;
        port_row = NULL;

        /* If the interface row is modified then update the hw_intf_config
               for the corresponding port row */
        if (OVSREC_IDL_IS_ROW_MODIFIED(intf_row, idl_seqno)) {

            /* get the port row for an interface */
            if ((port_row = portd_get_port_row(intf_row)) != NULL) {
                VLOG_DBG("Port found for interface %s", intf_row->name);

                /* For each vrf in all_vrfs, update the port list */
                HMAP_FOR_EACH (vrf, node, &all_vrfs) {
                    VLOG_DBG("vrf %s to search port %s\n", vrf->name,
                             port_row->name);
                    port = portd_port_lookup(vrf, port_row->name);
                    if (port) {
                        break;
                    }
                }

                if(!port) {
                    /* No port for this interface */
                    VLOG_DBG("No port found for interface %s", intf_row->name);
                }
            } else {
                VLOG_DBG("No port row for interface %s in ovsdb",
                         intf_row->name);
            }
            /*
             * Check if the user_config column changed.
             */
            if (OVSREC_IDL_IS_COLUMN_MODIFIED(ovsrec_interface_col_user_config,
                                              idl_seqno)) {
                /* Bring up kernel interface */
                cur_state = (char *)smap_get(&intf_row->user_config,
                                             INTERFACE_USER_CONFIG_MAP_ADMIN);
                if (cur_state != NULL &&
                    !strcmp(cur_state, OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP)) {
                    portd_interface_up_down(intf_row->name,
                                            OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP);
                } else {
                    portd_interface_up_down(intf_row->name,
                                            OVSREC_INTERFACE_USER_CONFIG_ADMIN_DOWN);
                }

                if(port) {
                    /* Set port hw_config:enable based on interface state */
                    /* Get interface state */
                    if (cur_state &&
                        (VTYSH_STR_EQ(cur_state,
                                      OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP))) {
                        intf_admin = true;
                    }
                    /* Get port state */
                    if (port_row->admin &&
                        (VTYSH_STR_EQ(port_row->admin,
                                      PORT_CONFIG_ADMIN_DOWN))) {
                        port_admin = false;
                    }
                    /* The final state is the 'and operation' between
                       the port admin and the interface admin */
                    port->hw_cfg_enable = (intf_admin && port_admin);
                    portd_set_hw_cfg(port, port_row);
                }
            }

            /*
             * Check if the hw_intf_config column changed.
             */
            if (OVSREC_IDL_IS_COLUMN_MODIFIED(ovsrec_interface_col_hw_intf_config,
                                              idl_seqno))
            {
                hw_intf_config_mtu = (char *)smap_get(&intf_row->hw_intf_config,
                                             INTERFACE_HW_INTF_CONFIG_MAP_MTU);

                if (hw_intf_config_mtu != NULL) {
                    portd_set_interface_mtu(intf_row->name,
                                            atoi(hw_intf_config_mtu));
                }
            }

            /*
             * Check if the admin_state column changed.
             * FIXME We should really be looking for kernel interface
             *       state using netlink instead of admin_state which
             *       is actually the physical hardware interface state
             */
            if (port && OVSREC_IDL_IS_COLUMN_MODIFIED(
                    ovsrec_interface_col_admin_state, idl_seqno)) {

                if (strcmp(intf_row->admin_state,
                        PORT_INTERFACE_ADMIN_UP) == 0) {

                    struct net_address *addr, *next_addr;
                    /*
                     * If the interface event is administratively forced to,
                     * 'OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP' reprogram the
                     * primary port address and all the secondary port addresses
                     * on the port. This needs to be done for IPv6 since
                     * the IPv6 addresses get deleted from the kernel when
                     * the kernel interface is administratively forced
                     * 'OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP'.
                     */
                    VLOG_DBG("Reprogramming the IPv6 address again since "
                            "the interface is forced up again");

                    if (port->ip6_address) {
                        nl_add_ip_address(RTM_NEWADDR, port->name,
                                          port->ip6_address, AF_INET6, false);
                    }

                    HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node,
                                        &port->secondary_ip6addr) {
                        nl_add_ip_address(RTM_NEWADDR, port->name,
                                          addr->address, AF_INET6, true);
                    }
                }
            }
        }
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

/**
 * Function: portd_del_internal_vlan
 * Param:
 *      interface_vid: ID of the internal VLAN that must be removed from default
 *      bridge row.
 * Description: Delete a VLAN from bridge table. Specifically, delete internal
 *              VLAN from default-bridge row.
 */
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

/* FIXME - update port table status column with error if no VLAN allocated. */
static int
portd_alloc_internal_vlan(void)
{
    int i, j;
    const struct ovsrec_bridge *br_row = NULL;
    const struct ovsrec_system *sys = NULL;
    unsigned long *vlans_bmp;
    bool ascending;
    int vlan_allocated = -1;

    int min_internal_vlan, max_internal_vlan;
    const char *internal_vlan_policy;

    sys = ovsrec_system_first(idl);

    if (sys) {
        min_internal_vlan =
                smap_get_int(&sys->other_config,
                             SYSTEM_OTHER_CONFIG_MAP_MIN_INTERNAL_VLAN,
                             DFLT_SYSTEM_OTHER_CONFIG_MAP_MIN_INTERNAL_VLAN_ID);
        max_internal_vlan =
                smap_get_int(&sys->other_config,
                             SYSTEM_OTHER_CONFIG_MAP_MAX_INTERNAL_VLAN,
                             DFLT_SYSTEM_OTHER_CONFIG_MAP_MAX_INTERNAL_VLAN_ID);
        internal_vlan_policy =
                smap_get(&sys->other_config,
                         SYSTEM_OTHER_CONFIG_MAP_INTERNAL_VLAN_POLICY);
        if (!internal_vlan_policy) {
            internal_vlan_policy =
                SYSTEM_OTHER_CONFIG_MAP_INTERNAL_VLAN_POLICY_ASCENDING_DEFAULT;
        }
        VLOG_DBG("min_internal : %d, %d, %s",
                  min_internal_vlan, max_internal_vlan,
                  internal_vlan_policy);

        /* Check if internal VLAN policy is valid */
        if ((strcmp(
                internal_vlan_policy,
                SYSTEM_OTHER_CONFIG_MAP_INTERNAL_VLAN_POLICY_ASCENDING_DEFAULT) != 0) &&
            (strcmp(
                internal_vlan_policy,
                SYSTEM_OTHER_CONFIG_MAP_INTERNAL_VLAN_POLICY_DESCENDING) != 0)) {
            VLOG_ERR("Unknown internal vlan policy '%s'",
                      internal_vlan_policy);
            return -1;
        }
    } else {
        VLOG_ERR("Unable to access system table in db.");
        return -1;
    }

    ascending = (strcmp(
                    internal_vlan_policy,
                    SYSTEM_OTHER_CONFIG_MAP_INTERNAL_VLAN_POLICY_ASCENDING_DEFAULT) == 0);

    OVSREC_BRIDGE_FOR_EACH (br_row, idl) {
        if (!strcmp(br_row->name, DEFAULT_BRIDGE_NAME)) {
            /* Set bitmap to identify available VLANs */
            vlans_bmp = bitmap_allocate(VLAN_BITMAP_SIZE);
            for (i = 0; i < br_row->n_vlans; i++) {
                struct ovsrec_vlan *vlan_row = br_row->vlans[i];
                bitmap_set1(vlans_bmp, vlan_row->id);
            }
            /* Loop through vlan bitmap and identify an available VLAN */
            for (j = ascending ? min_internal_vlan : max_internal_vlan;
                 ascending ? j <= max_internal_vlan : j >= min_internal_vlan;
                 ascending ? j++ : j--) {
                if (!bitmap_is_set(vlans_bmp,j)) {
                    VLOG_DBG("Allocated internal vlan (%d)", j);
                    vlan_allocated = j;
                    break;
                }
            }
            free(vlans_bmp);
        }
    }
    return vlan_allocated;
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

/* FIXME - move internal_vlan functions to a separate file */
static void
portd_add_internal_vlan(struct port *port, struct ovsrec_port *port_row)
{
    int vid;
    int require_vlan;
    const struct ovsrec_subsystem *ovs_subsys;

    /* FIXME: handle multiple subsystems. */
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
        portd_set_status_error(port_row, PORT_STATUS_MAP_ERROR_NO_INTERNAL_VLAN);
        return;
    }

    portd_create_vlan_row(vid, port_row);
    port->internal_vid = vid;

    portd_set_hw_cfg(port, port_row);

    return;
}

/* create port in cache */
static void
portd_port_create(struct vrf *vrf, struct ovsrec_port *port_row)
{
    struct port *port;

    port = xzalloc(sizeof *port);
    port->vrf = vrf;
    port->name = xstrdup(port_row->name);
    port->type = NULL; /* regular (non-intervlan) interface */
    port->cfg = port_row;
    port->internal_vid = -1;
    port->hw_cfg_enable = false;
    hmap_init(&port->secondary_ip4addr);
    hmap_init(&port->secondary_ip6addr);
    hmap_insert(&vrf->ports, &port->port_node, hash_string(port->name, 0));

    VLOG_DBG("port '%s' created", port->name);
    return;
}

/**
 * Add a new port to local cache or reconfigure existing port
 * if anything changed
 */
static void
portd_reconfig_ports(struct vrf *vrf, const struct shash *wanted_ports)
{
    struct shash_node *port_node;
    int vlan_id;
    bool port_admin = true;
    bool intf_admin = false;
    struct smap hw_cfg_smap;
    char *cur_state = NULL;

    SHASH_FOR_EACH (port_node, wanted_ports) {
        struct ovsrec_port *port_row = port_node->data;
        struct ovsrec_interface *intf_row = NULL;
        struct port *port = portd_port_lookup(vrf, port_row->name);
        if (!port) {
            VLOG_DBG("Creating new port %s vrf %s\n",port_row->name, vrf->name);
            portd_port_create(vrf, port_row);
            port = portd_port_lookup(vrf, port_row->name);

            if (portd_interface_type_internal_check(port_row, port_row->name) &&
                portd_port_in_bridge_check(port_row->name, DEFAULT_BRIDGE_NAME) &&
                portd_port_in_vrf_check(port_row->name, DEFAULT_VRF_NAME)) {

                portd_add_vlan_interface(DEFAULT_BRIDGE_NAME, port_row->name,
                                         *(port->cfg->tag));
                portd_interface_up_down(port_row->name, "up");

                port->type = xstrdup(OVSREC_INTERFACE_TYPE_INTERNAL);
            } else {
                /* Only assign internal VLAN if not already present. */
                smap_clone(&hw_cfg_smap, &port_row->hw_config);
                vlan_id = smap_get_int(&hw_cfg_smap,
                                       PORT_HW_CONFIG_MAP_INTERNAL_VLAN_ID, 0);
                if(vlan_id == 0) {
                    portd_add_internal_vlan(port, port_row);
                } else {
                    port->internal_vid = vlan_id;
                }
                smap_destroy(&hw_cfg_smap);
                if ((intf_row = portd_get_matching_interface_row(port_row)) != NULL) {
                    /* Its a VLAN or L3 interface */
                    VLOG_DBG("set up state for L3 and vlan interface\n");
                    /* Get interface state */
                    cur_state = (char *)smap_get(&intf_row->user_config,
                                                 INTERFACE_USER_CONFIG_MAP_ADMIN);
                    if (cur_state &&
                        (VTYSH_STR_EQ(cur_state,
                                      OVSREC_INTERFACE_USER_CONFIG_ADMIN_UP)))
                    {
                         intf_admin = true;
                    }
                    port->hw_cfg_enable = (intf_admin && port_admin);
                } else {
                    /* its a LAG */
                    /* set hw_config same as port admin_status */
                    VLOG_DBG("set up in LAG interface\n");
                    if ((port_row->admin == NULL) ||
                        (strcmp(port_row->admin, "up") == 0)) {
                        port->hw_cfg_enable = true;
                    } else {
                        port->hw_cfg_enable = false;
                    }
                }
                portd_set_hw_cfg(port, port_row);
            }

            portd_reconfig_ipaddr(port, port_row);
            VLOG_DBG("Port has IP: %s vrf %s\n", port_row->ip4_address,
                      vrf->name);

        } else if ((port) && OVSREC_IDL_IS_ROW_MODIFIED(port_row, idl_seqno)) {
            portd_reconfig_ipaddr(port, port_row);
            portd_port_admin_state_reconfigure(port, port_row);
            /* Port table row modified */
            VLOG_DBG("Port modified IP: %s vrf %s\n", port_row->ip4_address,
                     vrf->name);
        } else {
            VLOG_DBG("[%s:%d]: port %s exists, but no change in seqno",
                    __FUNCTION__, __LINE__, port_row->name);
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

/* remove the ports that are in local cache and not in db */
static void
portd_del_ports(struct vrf *vrf, const struct shash *wanted_ports)
{
    struct port *port, *next;

    HMAP_FOR_EACH_SAFE (port, next, port_node, &vrf->ports) {
        port->cfg = shash_find_data(wanted_ports, port->name);
        if (!port->cfg) {

            VLOG_DBG("Processing port delete port: %s type: %s",
                     port->name, port->type ? "inter-vlan" : "L3");

            /* Send delete interface to kernel */
            if (port->type &&
                (strcmp(port->type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0)) {
                portd_del_vlan_interface(port->name);
            }

            /* Port not present in the wanted_ports list. Destroy */
            portd_del_internal_vlan(port->internal_vid);
            portd_del_ipaddr(port);
            portd_port_destroy(port);
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

/**
 * One time request to get a dump of all the interfaces from the kernel
 * This is done during init, or daemon restart to keep the interface
 * state in sync with the OVSDB
 */
static void
portd_intf_config_on_init(void)
{
    struct rtattr *rta;
    struct {
        struct nlmsghdr hdr;
        struct rtgenmsg gen;
    } req;

    memset (&req, 0, sizeof(req));

    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_type = RTM_GETLINK;

    req.gen.rtgen_family = AF_PACKET;

    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
    rta->rta_len = RTA_LENGTH(4);

    if (send(init_sock, &req, req.hdr.nlmsg_len, 0) == -1) {
        VLOG_ERR("Netlink failed to send message for link dump");
        return;
    }
    /* Process the response from kernel */
    VLOG_DBG("Interfaces dump request sent on init");

    nl_msg_process(NULL, init_sock, true);
}

/**
 * This function will delete VLANs which no longer point to L3 ports.
 * There are two cases:
 * 1. The daemon crashed and an L3 interface became L2. The internal VLAN which
 *    was previously pointing to the L3 interface needs to be deleted.
 * 2. The daemon crashed and an interface went from L3 to L2 and back to L3.
 *    A new internal VLAN would be assigned as it is considered
 *    a new L3 interface. The previous internal VLAN needs to be removed.
 */
static void
portd_vlan_config_on_init(void)
{
    const struct ovsrec_vlan *int_vlan_row;
    struct smap vlan_internal_smap, hw_cfg_smap;
    struct ovsrec_port *port_row;
    int vlan_id;

    OVSREC_VLAN_FOR_EACH(int_vlan_row, idl) {
        smap_clone(&vlan_internal_smap, &int_vlan_row->internal_usage);
        /* Check to see if VLAN is of type 'internal' */
        if (!smap_is_empty(&vlan_internal_smap)) {
            const char *port_name = smap_get(&vlan_internal_smap,
                    VLAN_INTERNAL_USAGE_L3PORT);
            port_row = portd_port_db_lookup(port_name);
            smap_clone(&hw_cfg_smap, &port_row->hw_config);
            vlan_id = smap_get_int(&hw_cfg_smap,
                    PORT_HW_CONFIG_MAP_INTERNAL_VLAN_ID, 0);
            /* Checks for the following cases:
             * 1. Port has no internal VLAN id
             * 2. Port has a VLAN id which is different */
            if (vlan_id == 0 || int_vlan_row->id != vlan_id) {
                VLOG_DBG("Deleting the internal VLAN : %ld", int_vlan_row->id);
                portd_del_internal_vlan(int_vlan_row->id);
            }
            smap_destroy(&hw_cfg_smap);
        }
        smap_destroy(&vlan_internal_smap);
    }
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

/* Checks to see if:
 * vrf has been added/deleted.
 * port has been added/deleted from a vrf.
 * port has been modified (IP address(es)).
 * interface has been created in the kernel.
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

    /* In case the daemon restarts, ensure:
     * 1. Unused internal VLANs are deleted.
     * 2. IP addresses between DB and kernel are in sync.
     * 3. Interfaces link state (up/down) are in sync with DB.
     * 4. Intervlan interfaces on the kernel are in sync with DB.
     */
    if (portd_config_on_init) {
        /* Open an init sock to process reconfiguration */
        portd_netlink_socket_open(&init_sock, true);
        portd_vlan_config_on_init();
        portd_ipaddr_config_on_init();
        portd_intf_config_on_init();
    }

    portd_add_del_ports();

    /* IP addresses on kernel and DB are already in sync on init.
       Skipping this function on init */
    if (!portd_config_on_init) {
        /*
         * Read any OVSDB interface changes and
         * apply configurations
         */
        portd_handle_interface_config_mods();
    }

    if (portd_config_on_init) {
        portd_config_on_init = false;
        /* Close the init socket as it is not needed anymore */
        close(init_sock);
    }
    /* After all changes are done, update the seqno. */
    idl_seqno = new_idl_seqno;
    return;
}

static void
portd_service_netlink_messages (void)
{
    if (!portd_config_on_init) {
        /*
         * Get kernel notifications about interface creations
         * and update the kernel interface with IFF_UP/~IFF_UP
         * as per DB configurations
         */
        if (nl_sock > 0) {
            nl_msg_process(NULL, nl_sock, false);
        }
    }
}

static void
portd_run(void)
{
    ovsdb_idl_run(idl);

    if (ovsdb_idl_is_lock_contended(idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&rl, "another ops-portd process is running, "
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
    portd_service_netlink_messages();
    if (commit_txn) {
        ovsdb_idl_txn_commit_block(txn);
    }
    ovsdb_idl_txn_destroy(txn);
    VLOG_INFO_ONCE("%s (ops-portd) %s", program_name, VERSION);

    /* FIXME - verify db write was successful, else retry. */
    /* FIXME - cur_cfg delete once after system init */
}

static void
portd_netlink_recv_wait__ (void)
{
    if(nl_sock > 0 && system_configured) {
        poll_fd_wait(nl_sock, POLLIN);
    }
}

static void
portd_wait(void)
{
    ovsdb_idl_wait(idl);
    portd_netlink_recv_wait__();
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
    printf("%s: OPS portd daemon\n"
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
ops_portd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
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
    unixctl_command_register("exit", "", 0, 0, ops_portd_exit, &exiting);

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
        }
        poll_block();
    }
    portd_exit();
    unixctl_server_destroy(unixctl);

    return 0;
}
