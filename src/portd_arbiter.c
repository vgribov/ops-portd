/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <smap.h>
#include <openvswitch/vlog.h>

#include <openswitch-idl.h>
#include <vswitch-idl.h>

#include "portd.h"

VLOG_DEFINE_THIS_MODULE(portd_arbiter);

struct portd_arbiter_class portd_arbiter;

/*!
 * @brief      A utility function to get the value associated with
 *             a given port layer protocol.
 *
 * @param[in]  proto    The enumeration value of the protocol.
 *
 * @return     The name associated with the protocol.
 */
const char *
portd_arbiter_get_proto_name(enum ovsrec_port_forwarding_state_proto_e proto)
{
    /* Switch case of protocols currently considered by the arbiter */
    switch (proto) {
        case PORT_FORWARDING_STATE_PROTO_LACP:
            return PORT_FORWARDING_STATE_PROTOCOL_LACP;
        case PORT_FORWARDING_STATE_PROTO_MSTP:
            return PORT_FORWARDING_STATE_PROTOCOL_MSTP;
        default:
            return NULL;
    }
}

/*!
 * @brief      A utility function to get OVSDB key name for
 *             the forwarding state for a given layer.
 *
 * @param[in]  layer    The enumeration value of the layer.
 *
 * @return     The OVSDB key name associated with the layer.
 */
const char *
portd_arbiter_get_layer_key(enum ovsrec_port_forwarding_state_layer_e layer)
{
    switch (layer) {
        case PORT_FORWARDING_STATE_LAYER_AGGREGATION:
            return PORT_FORWARDING_STATE_MAP_PORT_AGGREGATION_FORWARDING;
        case PORT_FORWARDING_STATE_LAYER_LOOP_PROTECTION:
            return PORT_FORWARDING_STATE_MAP_PORT_LOOP_PROTECTION_FORWARDING;
        default:
            return NULL;
    }
}

/*!
 * @brief      A utility function to get OVSDB key name for
 *             the asserting protocol for a given layer.
 *
 * @param[in]  layer    The enumeration value of the layer.
 *
 * @return     The OVSDB key name associated with the asserting
 *             protocol.
 */
const char *
portd_arbiter_get_layer_owner_key(enum ovsrec_port_forwarding_state_layer_e layer)
{
    switch (layer) {
        case PORT_FORWARDING_STATE_LAYER_AGGREGATION:
            return PORT_FORWARDING_STATE_MAP_PORT_AGGREGATION_BLOCKED_REASON;
        case PORT_FORWARDING_STATE_LAYER_LOOP_PROTECTION:
            return PORT_FORWARDING_STATE_MAP_PORT_LOOP_PROTECTION_BLOCKED_REASON;
        default:
            return NULL;
    }
}

/*!
 * @brief      A utility function to translate the boolean
 *             state value to string stored in OVSDB.
 *
 * @param[in]  blocked    Boolean value to denote blocked or not.
 *
 * @return     String associated with the forwarding state.
 */
const char *
portd_arbiter_get_state_value(bool blocked)
{
    return blocked ?
            PORT_FORWARDING_STATE_FORWARDING_FALSE:
            PORT_FORWARDING_STATE_FORWARDING_TRUE;
}

/*!
 * @brief      A utility function to attach a new protocol to the existing list
 *             of protocols of a forwarding layer.
 *
 * @param[in,out]  head     The head of the linked list of protocols.
 * @param[in]      proto    The new protocol to be attached to the list.
 *
 * @return     Nothing
 */
void
portd_arbiter_attach_proto(struct portd_arbiter_proto_class **head,
                           struct portd_arbiter_proto_class *proto)
{
    struct portd_arbiter_proto_class *node = *head;

    /* If the head is null, list is empty. Return the current node as head */
    if (node == NULL) {
        *head = proto;
    } else {
        /* Walk the list from head till we reach the last node */
        while (node->next != NULL) {
            node = node->next;
        }
        /* Attach the new node to the list */
        node->next = proto;
    }
}

/*!
 * @brief      A utility function to attach a new forwarding layer to the
 *             existing list forwarding layers for an port.
 *
 * @param[in,out]  head     The head of the linked list of forwarding layers.
 * @param[in]      layer    The new layer to be attached to the list.
 *
 * @return     Nothing
 */
void
portd_arbiter_attach_layer(struct portd_arbiter_layer_class **head,
                           struct portd_arbiter_layer_class *layer)
{
    struct portd_arbiter_layer_class *node = *head;

    /* If the head is null, list is empty. Return the current node as head. */
    if (node == NULL) {
        *head = layer;
    } else {
        /* Walk the list from head till we reach the last node */
        while (node->next != NULL) {
            node = node->next;
        }
        /* Attach the new node to the list and point it to the previous node */
        node->next = layer;
        layer->prev = node;
    }
}

/*!
 * @brief      Callback function to run the arbiter algorithm for a given
 *             protocol operating at a given layer of a given port.
 *
 * @param[in]       proto     The pointer to the protocol data structure.
 * @param[in]       port     The port for which the arbiter is running.
 *
 * @return     true     If the current run deemed the forwarding state of the
 *                      port layer to be blocked.
 *             false    If the current run deemed the forwarding state of the
 *                      port layer to not be blocked.
 */
bool
portd_arbiter_proto_run(struct portd_arbiter_proto_class *proto,
                        const struct ovsrec_port *port)
{
    bool block;

    /* Get the view of the forwarding state for the port for
     * the current protocol. */
    block = (proto->get_state) ? proto->get_state(port) : false;

    if (block) {
        /* Check if the current forwarding state of this layer is already
         * blocked. */
        if (proto->layer->blocked) {
            /* Check if the current asserting protocol is of lower precedence
             * than the current protocol.
             * If yes, change the owner to current protocol.  */
            if (proto->id < proto->layer->owner) {
                VLOG_DBG(
                        "Changing owner of %d to %d for port %s",
                        proto->layer->id, proto->id, port->name);
                proto->layer->owner = proto->id;
            }
        } else {
            VLOG_DBG(
                    "Changing status of %d to blocked with owner as %d "
                    "for port %s",
                    proto->layer->id, proto->id, port->name);
            /* Set the forwarding state for this layer to block and set the
             * owner as current protocol. */
            proto->layer->blocked = true;
            proto->layer->owner = proto->id;
        }
    } else {
        /* Check if the current forwarding state of this layer is already blocked. */
        if (proto->layer->blocked) {
            /* Check if current protocol is the current owner.
             * If yes, clear the owner and move the state to forwarding. */
            if (proto->id == proto->layer->owner) {
                VLOG_DBG(
                        "Changing status of %d to forwarding with owner %d "
                        "cleared for port %s",
                        proto->layer->id, proto->id, port->name);
                proto->layer->owner = PORT_FORWARDING_STATE_PROTO_NONE;
                proto->layer->blocked = false;
            }
        }
    }

    return block;
}

/*!
 * @brief      Callback function to run the arbiter algorithm for a given
 *             forwarding layer of a given port.
 *
 * @param[in]       layer     The pointer to the f/w layer data structure.
 * @param[in]       port     The port for which the arbiter is running.
 *
 * @return     true     If the current run deemed the forwarding state of the
 *                      port layer to be blocked.
 *             false    If the current run deemed the forwarding state of the
 *                      port layer to not be blocked.
 */
bool
portd_arbiter_layer_run(struct portd_arbiter_layer_class *layer,
                        const struct ovsrec_port *port)
{
    struct portd_arbiter_proto_class *proto;
    const char *if_state;
    bool block;

    /* Check if the forwarding state of the previous layer is blocked. */
    if (layer->prev && layer->prev->blocked) {
        /* Set the current layer as blocked and remove the owner. */
        VLOG_DBG(
            "Blocking %d for port %s because forwarding layer %d is blocked",
            layer->id, port->name, layer->prev->id);
        layer->blocked = true;
        layer->owner = PORT_FORWARDING_STATE_PROTO_NONE;
        return true;
    }

    /* Check if the admin state of the port is down */
    if (port->admin && (VTYSH_STR_EQ(port->admin, PORT_CONFIG_ADMIN_DOWN))) {
        /* Set the current layer as blocked and remove the owner. */
        if (!layer->blocked) {
            VLOG_DBG("Blocking %d for port %s because the admin state is down",
                     layer->id, port->name);
        }

        layer->blocked = true;
        layer->owner = PORT_FORWARDING_STATE_PROTO_NONE;
        return true;
    }

    /* Check if the interface attached to the port is down
     * for a non bonded port.
     * For bonds, LACP would return the overall port status. */
    if (port->n_interfaces == 1) {
        struct ovsrec_interface *iface = port->interfaces[0];
        if_state = smap_get(&iface->forwarding_state, INTERFACE_FORWARDING_STATE_MAP_FORWARDING);
        if (if_state && (VTYSH_STR_EQ(if_state, INTERFACE_FORWARDING_STATE_FORWARDING_FALSE))) {
            /* Set the current layer as blocked and remove the owner. */
            if (!layer->blocked) {
                VLOG_DBG("Blocking %d for port %s because the interface state is down",
                         layer->id, port->name);
            }

            layer->blocked = true;
            layer->owner = PORT_FORWARDING_STATE_PROTO_NONE;
            return true;
        }
    }

    proto = layer->protos;

    /* Walk through all the protocols operating at this layer and determine the
     * new forwarding state */
    while (proto != NULL) {
        if (proto->run) {
            block = proto->run(proto, port);
            if (block) {
                return true;
            }
        }
        proto = proto->next;
    }

    /* None of the protocols set the layer as blocking.
     * Move the state to forwarding */
    layer->blocked = false;
    layer->owner = PORT_FORWARDING_STATE_PROTO_NONE;

    return false;
}

/*!
 * @brief      Function to run the arbiter algorithm for a given port.
 *
 * @param[in]       port     The port for which the arbiter is running.
 * @param[in,out]   forwarding_state The forwarding state column of OVSDB.
 *
 * @return     Nothing
 */
void
portd_arbiter_port_run(const struct ovsrec_port *port,
                       struct smap *forwarding_state)
{
    struct portd_arbiter_layer_class *last_layer, *layer;
    const char *layer_key, *layer_owner_key, *owner_name, *state_value;

    last_layer = layer = portd_arbiter.layers;

    /* Walk from the first to last applicable forwarding layers for port */
    while (layer != NULL) {
        /* Trigger the current layer checks if it has a registered function. */
        if (layer->run) {
            layer->run(layer, port);
        }

        /* Get OVSDB key name for setting the forwarding state of the current
         * layer */
        layer_key = portd_arbiter_get_layer_key(layer->id);
        /* Get OVSDB key name for setting the owner for this layer dictating
         * the forwarding state. */
        layer_owner_key = portd_arbiter_get_layer_owner_key(layer->id);
        /* Get name for the current asserting owner for this layer */
        owner_name = portd_arbiter_get_proto_name(layer->owner);
        /* Get the value associated with the forwarding state of the current
         * layer */
        state_value = portd_arbiter_get_state_value(layer->blocked);

        /* Check if the current layer has an owner */
        if (layer->owner != PORT_FORWARDING_STATE_PROTO_NONE) {
            /* There is an owner. Set the forwarding state and the owner for
             * this layer based on the information cached in the layer data
             * structure. */
            smap_replace(forwarding_state, layer_key, state_value);
            smap_replace(forwarding_state, layer_owner_key, owner_name);
        } else {
            /* There is no owner. Check if the current forwarding state of
             * the layer is blocked. */
            if (layer->blocked) {
                /* The forwarding state is blocked. This implies:
                 * - The admin/operator state is down.
                 * - The forwarding state of a previous layer is blocked.
                 *
                 * Remove the key,value pair for the forwarding state of this
                 * layer and the asserting protocol. */
                smap_remove(forwarding_state, layer_key);
                smap_remove(forwarding_state, layer_owner_key);
            } else {
                /* The forwarding state is open. Set the forwarding state as
                 * open for current layer and remove any asserting protocol. */
                smap_replace(forwarding_state, layer_key, state_value);
                smap_remove(forwarding_state, layer_owner_key);
            }
        }

        /* Move to the next forwarding layer in the hierarchy */
        last_layer = layer;
        layer = layer->next;
    }

    /* Set the forwarding state of the port based on the forwarding state
     * of the last layer.
     * If there isn't one, set the port state as forwarding. */
    if (last_layer) {
        state_value = portd_arbiter_get_state_value(last_layer->blocked);
        smap_replace(forwarding_state, PORT_FORWARDING_STATE_MAP_FORWARDING, state_value);
    } else {
        smap_replace(forwarding_state, PORT_FORWARDING_STATE_MAP_FORWARDING,
                     PORT_FORWARDING_STATE_FORWARDING_TRUE);
    }
}

/*!
 * @brief      Function to determine the forwarding state of an port
 *             from "lacp" perspective.
 *
 * @param[in]  port     The port for which the arbiter is running.
 *
 * @return     true     If lacp deems the port should be blocked.
 *             false    If lacp deems the port should be forwarding.
 */
bool
portd_arbiter_lacp_state(const struct ovsrec_port *port)
{
    /* Get the forwarding state for this protocol. */
    const char *bond_status;
    bond_status = smap_get(&port->bond_status, PORT_BOND_STATUS_MAP_STATE);
    if (!bond_status || VTYSH_STR_EQ(bond_status, PORT_BOND_STATUS_UP)) {
        return false;
    } else {
        return true;
    }
    return false;
}

/*!
 * @brief      Function to determine the forwarding state of an port
 *             from "MSTP" perspective.
 *
 * @param[in]  port     The port for which the arbiter is running.
 *
 * @return     true     If mstp deems the port should be blocked.
 *             false    If mstp deems the port should be forwarding.
 */
bool
portd_arbiter_mstp_state(const struct ovsrec_port *port)
{
    const char *state;
    /* Get the forwarding state for this protocol */
    state = smap_get(&port->hw_config, "block_all_mstp");
    if (state && VTYSH_STR_EQ(state, "true")) {
        return true;
    } else {
        return false;
    }
}

/*!
 * @brief      Function to register the forwarding layer 'aggregation' and all
 *             the applicable protocols at this layer with the arbiter.
 *
 * @param[in,out]  layer_head     The head of the linked list of forwarding
 *                                layers.
 *
 * @return     Nothing
 */
void
portd_arbiter_layer_aggregation_register(
        struct portd_arbiter_layer_class **layer_head)
{
    struct portd_arbiter_layer_class *aggregation;
    struct portd_arbiter_proto_class *proto, *proto_head = NULL;

    /* Define and register the aggregation layer */
    aggregation = xzalloc(sizeof(struct portd_arbiter_layer_class));
    aggregation->id = PORT_FORWARDING_STATE_LAYER_AGGREGATION;
    aggregation->owner = PORT_FORWARDING_STATE_PROTO_NONE;
    aggregation->run = portd_arbiter_layer_run;
    aggregation->next = NULL;
    aggregation->prev = NULL;

    /* Define and register the protocols running at aggregation layer.
     * The ones registered first trumps in precedence over the
     * ones following it. */

    /* Register lacp */
    proto = xzalloc(sizeof(struct portd_arbiter_proto_class));
    proto->id = PORT_FORWARDING_STATE_PROTO_LACP;
    proto->run = portd_arbiter_proto_run;
    proto->get_state = portd_arbiter_lacp_state;
    proto->layer = aggregation;
    proto->next = NULL;
    portd_arbiter_attach_proto(&proto_head, proto);

    aggregation->protos = proto_head;

    /* Attach the aggregation layer to the list */
    portd_arbiter_attach_layer(layer_head, aggregation);

    return;
}

/*!
 * @brief      Function to register the forwarding layer 'loop protection'
 *             and all the applicable protocols at this layer with the arbiter.
 *
 * @param[in,out]  layer_head     The head of the linked list of forwarding
 *                                layers.
 *
 * @return     Nothing
 */
void
portd_arbiter_layer_loop_protection_register(
        struct portd_arbiter_layer_class **layer_head)
{
    struct portd_arbiter_layer_class *loop_protect;
    struct portd_arbiter_proto_class *proto, *proto_head = NULL;

    /* Define and register the loop_protect layer */
    loop_protect = xzalloc(sizeof(struct portd_arbiter_layer_class));
    loop_protect->id = PORT_FORWARDING_STATE_LAYER_LOOP_PROTECTION;
    loop_protect->owner = PORT_FORWARDING_STATE_PROTO_NONE;
    loop_protect->run = portd_arbiter_layer_run;
    loop_protect->next = NULL;
    loop_protect->prev = NULL;

    /* Define and register the protocols running at loop_protect layer.
     * The ones registered first trumps in precedence over the
     * ones following it. */

    /* Register MSTP */
    proto = xzalloc(sizeof(struct portd_arbiter_proto_class));
    proto->id = PORT_FORWARDING_STATE_PROTO_MSTP;
    proto->run = portd_arbiter_proto_run;
    proto->get_state = portd_arbiter_mstp_state;
    proto->layer = loop_protect;
    proto->next = NULL;
    portd_arbiter_attach_proto(&proto_head, proto);

    loop_protect->protos = proto_head;

    /* Attach the loop protection layer to the list */
    portd_arbiter_attach_layer(layer_head, loop_protect);

    return;
}

/*!
 * @brief      Function to initialize the port arbiter.
 *
 * @return     Nothing
 */
void
portd_arbiter_init(void)
{
    memset(&portd_arbiter, 0, sizeof(struct portd_arbiter_class));

    /* Initialize and attach the port 'aggregation' layer */
    portd_arbiter_layer_aggregation_register(&portd_arbiter.layers);
    /* Initialize and attach the port 'loop_protection' layer */
    portd_arbiter_layer_loop_protection_register(&portd_arbiter.layers);

    return;
}
