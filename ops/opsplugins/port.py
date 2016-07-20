from opsvalidator.base import *
from opsvalidator import error
from opsvalidator.error import ValidationError
from opsrest.utils import *
from tornado.log import app_log
import socket
import struct
from array import array


def is_ip4_valid(address):
    ip_parse = address.split('/')
    if len(ip_parse) != 2:
        return False
    if not ip_parse[1].isdigit():
        return False
    if int(ip_parse[1]) not in range(33):
        return False
    if ip_parse[0].count('.') != 3:
        return False
    try:
        socket.inet_pton(socket.AF_INET, ip_parse[0])
    except socket.error:
        return False
    return True


def is_ip6_valid(address):
    ip_parse = address.split('/')
    if len(ip_parse) != 2:
        return False
    if not ip_parse[1].isdigit():
        return False
    if int(ip_parse[1]) not in range(129):
        return False
    try:
        socket.inet_pton(socket.AF_INET6, ip_parse[0])
    except socket.error:
        return False
    return True


def ip_address_masked(address, masklen, ip_type):
    ip_as_long = None
    ipv4_mask = 0xFFFFFFFF
    ipv6_mask = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    if ip_type == "ipv4":
        try:
            addr = array('L', struct.unpack(
                '!1L', socket.inet_pton(socket.AF_INET, address)))
            ip_as_long = addr[0]
            ipv4_mask = ipv4_mask << (32 - masklen)
            ip_as_long = ip_as_long & ipv4_mask

        except socket.error:
            return None
    else:
        # try IPv6
        try:
            addr = array('L', struct.unpack(
                '!4L', socket.inet_pton(socket.AF_INET6, address)))
            addr.reverse()
            ip_as_long = sum(addr[i] << (i * 32) for i in range(len(addr)))
            ipv6_mask = ipv6_mask << (128 - masklen)
            ip_as_long = ip_as_long & ipv6_mask

        except socket.error:
            return None
    return ip_as_long


def get_vrf_row_for_port(idl, port_name):
    for ovs_rec in idl.tables["VRF"].rows.itervalues():
        if ovs_rec.ports:
            for port in ovs_rec.ports:
                if port.name == port_name:
                    return ovs_rec.ports
    return None


def is_ip_overlapping(ip, ip_type, if_name, is_sec, port_row):
    port_ip_address = None
    port_ip_sec_address = []
    port_ip_subnet = None
    port_ip_sec_subnet = []
    ip_addr, ip_subnet = ip.split('/')
    ip_subnet = int(ip_subnet)
    if ip_type == "ipv6":
        if len(port_row.ip6_address) != 0:
            port_ip_address, port_ip_subnet = \
                port_row.ip6_address[0].split('/')
            port_ip_subnet = int(port_ip_subnet)

        for ip_sec in port_row.ip6_address_secondary:
            sec_ip, sec_subnet = ip_sec.split('/')
            port_ip_sec_address.append(dict(ip=sec_ip,
                                            subnet=int(sec_subnet)))
    else:
        if len(port_row.ip4_address) != 0:
            port_ip_address, port_ip_subnet = \
                port_row.ip4_address[0].split('/')
            port_ip_subnet = int(port_ip_subnet)
        for ip_sec in port_row.ip4_address_secondary:
            sec_ip, sec_subnet = ip_sec.split('/')
            port_ip_sec_address.append(dict(ip=sec_ip,
                                            subnet=int(sec_subnet)))

    if port_ip_address and port_ip_subnet:
        subnet = ip_subnet if ip_subnet < port_ip_subnet else port_ip_subnet
        ip_masked = ip_address_masked(ip_addr, subnet, ip_type)
        port_ip_masked = ip_address_masked(port_ip_address, subnet, ip_type)
        if ip_masked and port_ip_masked:
            if ip_masked == port_ip_masked:
                if if_name == port_row.name and not is_sec:
                    return False
                return True
        else:
           ##something went  wrong
            return False
    for ip_sec in port_ip_sec_address:
        subnet = \
            ip_subnet if ip_subnet < ip_sec['subnet'] else ip_sec['subnet']
        ip_masked = ip_address_masked(ip_addr, subnet, ip_type)
        port_ip_masked = ip_address_masked(ip_sec['ip'], subnet, ip_type)
        if ip_masked and port_ip_masked:
            if ip_masked == port_ip_masked:
                if (if_name == port_row.name) and is_sec and \
                        ip_subnet == ip_sec['subnet'] and \
                        ip_addr == ip_sec['ip']:
              #hit the same entry hence skip
                            continue
                return True
        else:
           ##something went  wrong
            return False
    return False


class PortValidator(BaseValidator):
    resource = "port"

    def validate_modification(self, validation_args):
        is_new = validation_args.is_new
        port_row = validation_args.resource_row
        idl = validation_args.idl
        is_sec = False
        ip_type = "ipv4"
        port_ip4 = None
        port_ip4_sec = None
        port_ip6 = None
        port_ip6_sec = None
        port_dict = {}
        if '_changes' in port_row.__dict__:
            port_dict = port_row.__dict__['_changes']

        if "ip4_address" in port_dict:
            port_ip4 = \
                utils.get_column_data_from_row(port_row,
                                               "ip4_address")
            if port_ip4:
                for port_ip in port_ip4:
                    if not is_ip4_valid(port_ip):
                        details =\
                            "ip[%s] is not valid" % (port_ip)
                        raise ValidationError(error.VERIFICATION_FAILED,
                                              details)
        if "ip4_address_secondary" in port_dict:
            port_ip4_sec = \
                utils.get_column_data_from_row(port_row,
                                               "ip4_address_secondary")
            if port_ip4_sec:
                for port_ip in port_ip4_sec:
                    if not is_ip4_valid(port_ip):
                        details =\
                            "ip[%s] is not valid" % (port_ip)
                        raise ValidationError(error.VERIFICATION_FAILED,
                                              details)
        if "ip6_address" in port_dict:
            port_ip6 = \
                utils.get_column_data_from_row(port_row,
                                               "ip6_address")
            if port_ip6:
                for port_ip in port_ip6:
                    if not is_ip6_valid(port_ip):
                        details =\
                            "ip[%s] is not valid" % (port_ip)
                        raise ValidationError(error.VERIFICATION_FAILED,
                                              details)
        if "ip6_address_secondary" in port_dict:
            port_ip6_sec = \
                utils.get_column_data_from_row(port_row,
                                               "ip6_address_secondary")
            if port_ip6_sec:
                for port_ip in port_ip6_sec:
                    if not is_ip6_valid(port_ip):
                        details =\
                            "ip[%s] is not valid" % (port_ip)
                        raise ValidationError(error.VERIFICATION_FAILED,
                                              details)

        port_name = utils.get_column_data_from_row(port_row, "name")
        vrf_row_ports = get_vrf_row_for_port(idl, port_name)

        if not vrf_row_ports:
            return

        if port_ip4:
            for port_ip in port_ip4:
                for port in vrf_row_ports:
                    if is_ip_overlapping(port_ip, "ipv4",
                                         port_name, False, port):
                        details =\
                            "ip[%s] overlap in port:%s" % (port_ip,
                                                           port.name)
                        raise ValidationError(error.VERIFICATION_FAILED,
                                              details)
        if port_ip4_sec:
            for port_ip in port_ip4_sec:
                for port in vrf_row_ports:
                    if is_ip_overlapping(port_ip, "ipv4",
                                         port_name, True, port):
                        details = \
                            "secondary ip[%s] overlap in port:%s" % (port_ip,
                                                                     port.name)
                        raise ValidationError(error.VERIFICATION_FAILED,
                                              details)
        if port_ip6:
            for port_ip in port_ip6:
                for port in vrf_row_ports:
                    if is_ip_overlapping(port_ip, "ipv6",
                                         port_name, False, port):
                        details =\
                            "ip[%s] overlap in port:%s" % (port_ip,
                                                           port.name)
                        raise ValidationError(error.VERIFICATION_FAILED,
                                              details)
        if port_ip6_sec:
            for port_ip in port_ip6_sec:
                for port in vrf_row_ports:
                    if is_ip_overlapping(port_ip, "ipv6",
                                         port_name, True, port):
                        details =\
                            "secondary ip[%s] overlap in port:%s" % (port_ip,
                                                                     port.name)
                        raise ValidationError(error.VERIFICATION_FAILED,
                                              details)

        app_log.debug('Port Validation Successful')
