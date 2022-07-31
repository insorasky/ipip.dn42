import re
import socket
from binascii import hexlify
import ipaddress

IPV4_PATTERN = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
IPV6_PATTERN = re.compile(
    r'^([\da-fA-F]{1,4}:){6}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^::([\da-fA-F]{1,'
    r'4}:){0,4}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,4}:):([\da-fA-F]{1,'
    r'4}:){0,3}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,4}:){2}:([\da-fA-F]{'
    r'1,4}:){0,2}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,4}:){3}:(['
    r'\da-fA-F]{1,4}:){0,1}((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,'
    r'4}:){4}:((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([\da-fA-F]{1,4}:){7}[\da-fA-F]{1,'
    r'4}$|^:((:[\da-fA-F]{1,4}){1,6}|:)$|^[\da-fA-F]{1,4}:((:[\da-fA-F]{1,4}){1,5}|:)$|^([\da-fA-F]{1,4}:){2}((:['
    r'\da-fA-F]{1,4}){1,4}|:)$|^([\da-fA-F]{1,4}:){3}((:[\da-fA-F]{1,4}){1,3}|:)$|^([\da-fA-F]{1,4}:){4}((:['
    r'\da-fA-F]{1,4}){1,2}|:)$|^([\da-fA-F]{1,4}:){5}:([\da-fA-F]{1,4})?$|^([\da-fA-F]{1,4}:){6}:$')


def ip2int(ip):
    if re.match(IPV4_PATTERN, ip) is not None:  # ipv4
        return int(hexlify(socket.inet_pton(socket.AF_INET, ip)), 16)
    elif re.match(IPV6_PATTERN, ip) is not None:  # ipv6
        return int(hexlify(socket.inet_pton(socket.AF_INET6, ip)), 16)
    else:
        raise ValueError('Not valid IP')


def ip_type(ip):
    if re.match(IPV4_PATTERN, ip) is not None:  # ipv4
        return 'ipv4'
    elif re.match(IPV6_PATTERN, ip) is not None:  # ipv6
        return 'ipv6'
    else:
        return 'unknown'


def ip_range(cidr):
    ip_ = cidr.split('/')[0]
    if re.match(IPV4_PATTERN, ip_) is not None:  # ipv4
        net = ipaddress.IPv4Network(cidr)
    elif re.match(IPV6_PATTERN, ip_) is not None:  # ipv6
        net = ipaddress.IPv6Network(cidr)
    else:
        raise ValueError('Invalid CIDR')
    return str(net[0]), str(net[-1])
