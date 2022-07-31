from config import *
import subprocess
from hashlib import md5
import time
import base64
from ip import *


class InvalidASNorIP(Exception):
    pass


class NoFingerprint(Exception):
    pass


def get_maintainer(asn_or_ip):
    data = subprocess.check_output(['whois', '-h', WHOIS_SERVER, asn_or_ip]).decode().strip()
    if data.endswith('% 404') or data.endswith('% This is the dn42 whois query service.'):
        raise InvalidASNorIP()
    source = [line.split('\n') for line in data.split('\n') if line.startswith('source:')][-1][0].strip().split(' ')[-1]
    if source == 'NEONETWORK':
        mnt = [line.split('\n') for line in data.split('\n') if line.startswith('admin-c:')][-1][0].strip().split(' ')[-1]
    else:
        mnt = [line.split('\n') for line in data.split('\n') if line.startswith('mnt-by:')][-1][0].strip().split(' ')[-1]
    asn = [item[0].strip().split(' ')[-1] for item in [line.split('\n') for line in data.split('\n') if line.startswith('aut-num:') or line.startswith('origin:')]]
    return asn, mnt, source


def get_auth_key(mntner):
    data = subprocess.check_output(['whois', '-h', WHOIS_SERVER, mntner]).decode().strip()
    if data[-5:] == '% 404':
        raise InvalidASNorIP()
    source = [line.split('\n') for line in data.split('\n') if line.startswith('source:')][-1][0].strip().split(' ')[-1]
    if source == 'NEONETWORK':
        return [('pgp-fingerprint', line[20:]) for line in data.split('\n') if line.startswith('pgp-fingerprint:')]
    else:
        lines = [line[20:] for line in data.split('\n') if line.startswith('auth:')]
    if len(lines) == 0:
        return []
    keys = [tuple(item.strip().split(' ', 1)) for item in lines]
    return keys


def get_key(arg):
    info, hash_str = arg.split(':')
    timestamp, asn = base64.b64decode(info).decode().split(':')
    data = f"{HASH_KEY};{asn};{arg};{get_maintainer(asn)};"
    return md5(data.encode()).hexdigest()


def check_asn(asn, arg, key):
    info, hash_str = arg.split(':')
    timestamp, asn2 = base64.b64decode(info).decode().split(':')
    if asn != asn2:  # ASN和参数中的ASN不一致
        return False
    timestamp = int(timestamp)
    current_time = time.time() * 1000
    if current_time - timestamp > 15 * 60 * 1000:  # 参数过期
        return False
    if key != get_key(arg):  # 密钥不匹配
        return False
    return True


def get_cidr(ip):
    data = subprocess.check_output(['whois', '-h', WHOIS_SERVER, ip]).decode().strip()
    if data.endswith('% 404') or data.endswith('% This is the dn42 whois query service.'):
        raise InvalidASNorIP()
    routes = []
    if ip_type(ip) == 'ipv4':
        routes = [line.split('\n') for line in data.split('\n') if line.startswith('route:')]
    elif ip_type(ip) == 'ipv6':
        routes = [line.split('\n') for line in data.split('\n') if line.startswith('route6:')]
    if len(routes) == 0:
        raise InvalidASNorIP()
    cidr = routes[-1][0].strip().split(' ')[-1]
    asn = [item[0].strip().split(' ')[-1] for item in [line.split('\n') for line in data.split('\n') if line.startswith('aut-num:') or line.startswith('origin:')]]
    return cidr, asn
