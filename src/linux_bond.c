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

/***************************************************************************
 *    File               : linux_bond.c
 *    Description        : Manages (creates, deletes, configures) Linux
 *                           bonding interfaces
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ops-utils.h>

#include <unixctl.h>
#include <dynamic-string.h>
#include <openswitch-idl.h>
#include <openswitch-dflt.h>
#include <openvswitch/vlog.h>
#include <poll-loop.h>
#include <hash.h>
#include <shash.h>

#include "linux_bond.h"

VLOG_DEFINE_THIS_MODULE(linux_bond);

#define MAX_FILE_PATH_LEN       100
#define READ                    "r"
#define WRITE_UPDATE            "w+"
#define BONDING_MASTERS_PATH    "/sys/class/net/bonding_masters"
#define BONDING_MODE_PATH       "/sys/class/net/%s/bonding/mode"
#define BONDING_SLAVES_PATH     "/sys/class/net/%s/bonding/slaves"
#define BONDING_CONFIGURATION   "/proc/net/bonding/%s"
#define BALANCE_XOR_MODE        "2"

/**
 * Deletes a Linux bond interface previously created.
 *
 * @param bond_name is the name of the bond to be deleted
 * @return true if the bond was deleted, false otherwise
 *
 */
bool delete_linux_bond(char* bond_name)
{
    FILE * masters_file;

    VLOG_INFO("bond: Deleting bond %s", bond_name);

    masters_file = fopen(BONDING_MASTERS_PATH, WRITE_UPDATE);

    if(masters_file) {
        fprintf (masters_file, "-%s", bond_name);
        fclose(masters_file);
        return true;
    }
    else {
        VLOG_ERR("bond: Failed to delete bond %s in linux", bond_name);
        return false;
    }
} /* delete_linux_bond */

/**
 * Creates a Linux bond interface.
 *
 * @param bond_name is the name of the bond to be created
 * @return true if the bond was created, false otherwise
 *
 */
bool create_linux_bond(char* bond_name)
{
    char file_path[MAX_FILE_PATH_LEN];
    FILE * masters_file;

    VLOG_INFO("bond: Creating bond %s", bond_name);

    masters_file = fopen (BONDING_MASTERS_PATH, WRITE_UPDATE);

    if(masters_file) {
        fprintf (masters_file, "+%s", bond_name);
        fclose(masters_file);

        snprintf(file_path, MAX_FILE_PATH_LEN, BONDING_MODE_PATH, bond_name);
        masters_file = fopen (file_path, WRITE_UPDATE);

        if(masters_file) {
            fprintf (masters_file, BALANCE_XOR_MODE);
            fclose(masters_file);
        }
        else {
            VLOG_ERR("bond: Failed to set bonding mode in bond %s",
                     bond_name);
            return false;
        }
    }
    else {
        VLOG_ERR("bond: Failed to create bond %s in linux", bond_name);
        return false;
    }
    return true;
} /* create_linux_bond */

/**
 * Adds a slave to a Linux bond
 *
 * @param bond_name is the name of the bond.
 * @param slave_name is the name of the slave interface to
 *           be added.
 * @return true if the slave was added to the bond, false otherwise
 *
 */
bool add_slave_to_bond(char* bond_name, char* slave_name)
{
    char file_path[MAX_FILE_PATH_LEN];
    FILE * slaves_file;

    VLOG_INFO("bond: Adding bonding slave %s to bond %s",
              slave_name, bond_name);

    snprintf(file_path, MAX_FILE_PATH_LEN, BONDING_SLAVES_PATH, bond_name);

    slaves_file = fopen (file_path, WRITE_UPDATE);

    if(slaves_file) {
        fprintf (slaves_file, "+%s", slave_name);
        fclose(slaves_file);
        return true;
    }
    else {
        VLOG_ERR("bond: Failed to add interface %s to bond %s",
                 slave_name, bond_name);
        return false;
    }
} /* add_slave_to_bond */

/**
 * Removes a slave from a Linux bond.
 *
 * @param bond_name is the name of the bond.
 * @param slave_name is the name of the slave interface to
 *           be removed.
 * @return true if the slave was removed from the bond, false otherwise
 *
 */
bool remove_slave_from_bond(char* bond_name, char* slave_name)
{
    char file_path[MAX_FILE_PATH_LEN];
    FILE * slaves_file;

    VLOG_INFO("bond: Removing bonding slave %s from bond %s",
             slave_name, bond_name);

    snprintf(file_path,MAX_FILE_PATH_LEN, BONDING_SLAVES_PATH, bond_name);

    slaves_file = fopen (file_path, WRITE_UPDATE);

    if(slaves_file) {
        fprintf (slaves_file, "-%s", slave_name);
        fclose(slaves_file);
        return true;
    }
    else {
        VLOG_ERR("bond: Failed to remove interface %s from bond %s",
                 slave_name, bond_name);
        return false;
    }
} /* remove_slave_from_bond */

/**
 * Dumps the Linux bonding driver configuration for a specified bond.
 *
 * @param ds pointer to struct ds that holds the debug output.
 * @param bond_name is the name of the bond.

 * @return void
 *
 */
void portd_bonding_configuration_file_dump(struct ds *ds, char* bond_name)
{
    ds_put_format(ds, "Configuration file for %s:\n", bond_name);
    char file_path[MAX_FILE_PATH_LEN];
    FILE * configuration_file;
    int char_to_print;

    snprintf(file_path, MAX_FILE_PATH_LEN, BONDING_CONFIGURATION, bond_name);
    configuration_file = fopen (file_path, READ);

    if(configuration_file) {
        while ((char_to_print = getc(configuration_file)) != EOF)
            ds_put_format(ds, "%c", char_to_print);
        ds_put_format(ds, "\n");
        fclose(configuration_file);
    }
    else {
        VLOG_ERR("bond: Failed to dump configuration file from bond %s",
                 bond_name);
    }
}
