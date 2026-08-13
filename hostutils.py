# coding=utf-8
"""
Host utils.
"""
from os.path import dirname
from re import compile
from sys import path

if dirname(__file__) not in path:
    path.append(dirname(__file__))

try:
    from .rdpdisconnect import get_rdp_sessions
except:
    from rdpdisconnect import get_rdp_sessions

# Patterns
ipReg = r'(([0-9]|\*|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(25[0-5]|\*|2[0-4][0-9]|1[0-9][0-9]|[1-9][' \
        r'0-9]|[0-9])'
ipCidrMsk = ipReg + r'\/(' + ipReg + '|(1[6-9]|2[0-9]|3[0-2]))'
ipRng = ipReg + r'\s*-\s*' + ipReg
ipPort = ipReg + r'(\:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9][0-9]|[1-5](\d){4}|[0-9](\d){0,' \
                 r'3}))?'
buildIP = ipCidrMsk + r'|' + ipRng + r'|' + ipPort


def isIpAddress(ipaddr, containPort=True):
    """
    Check and return True if IP Address match is correct.
    """
    try:
        if containPort:
            compile(r"(" + ipPort + r')$').fullmatch(ipaddr).group()
        else:
            compile(r"(" + ipReg + r')$').fullmatch(ipaddr).group()
        return True
    except AttributeError:
        return False


def ipList(listStr):
    """
    Collect any IP style from text lines.
    """
    return [xx.group() for xx in compile(buildIP).finditer(listStr.strip())]


def matchIp(ipaddr, tp='Any'):
    """
    Extract the current IP type or Port.
    """
    try:
        if tp.lower() == "ip":
            return compile(ipReg).search(ipaddr.strip()).group(0)
        elif tp.lower() == "port":
            port = r'(6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9][0-9]|[1-5](\d){4}|[0-9](\d){0,3})'
            return int(compile(port).search(ipaddr.strip()).group(0))
        return compile(buildIP).search(ipaddr.strip()).group()
    except AttributeError:
        return ''


def ipHosts():
    # Iterate through each connection and group them by user.
    for adr in get_rdp_sessions():
        # Get the process information.
        try:
            laddr = adr['client_ip']  # type: str
            if not laddr.startswith('127.0.0.1') and isIpAddress(laddr, False):
                # process = Process(conn.pid)
                # username = process.username()
                yield laddr
        except:
            continue
