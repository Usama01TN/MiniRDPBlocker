# -*- coding: utf-8 -*-
"""
Disconnect (or log off) RDP clients on THIS Windows host by their client IP.
Run this ON the RDP host, from an ELEVATED / Administrator prompt — ending
another user's session requires admin rights.
Disconnect vs. log off:
  - Disconnect (default): drops the remote connection but leaves the session
    running. The user's apps stay open and they can reconnect later.
  - Log off (--logoff): ends the session entirely; unsaved work is lost.
Usage:
    python rdpdisconnect.py 192.168.1.40                 # disconnect one IP
    python rdpdisconnect.py 192.168.1.40 10.0.0.5        # several IPs
    python rdpdisconnect.py 192.168.1.40 --logoff        # full logoff
    python rdpdisconnect.py --list                       # show sessions, change nothing
    python rdpdisconnect.py 192.168.1.40 --dry-run       # show what would happen
    python rdpdisconnect.py 192.168.1.40 -y              # skip the confirmation prompt
Windows only.
"""
from ctypes import wintypes, WinDLL, c_byte, c_void_p, wstring_at, WinError, windll, cast, c_int, Structure, byref, \
    get_last_error, POINTER
from argparse import ArgumentParser
from sys import exit

# ---------------------------------------------------------------------------
# WTS (Windows Terminal Services) API bindings.
# ---------------------------------------------------------------------------

wtsapi32 = WinDLL("wtsapi32.dll", use_last_error=True)
IsUserAnAdmin = windll.shell32.IsUserAnAdmin
WTS_CURRENT_SERVER_HANDLE = 0  # the local server.
WTS_INFO_USERNAME = 5  # WTSUserName
WTS_INFO_CLIENT_ADDRESS = 14  # WTSClientAddress
AF_INET = 2  # IPv4
AF_INET6 = 23  # IPv6
STATE_NAMES = {0: 'Active', 1: 'Connected', 2: 'ConnectQuery', 3: "Shadow", 4: 'Disconnected', 5: 'Idle', 6: 'Listen',
               7: 'Reset', 8: 'Down', 9: 'Init'}


class WTS_SESSION_INFO(Structure):
    """
    WTS_SESSION_INFO structure class.
    """
    _fields_ = [('SessionId', wintypes.DWORD), ('pWinStationName', wintypes.LPWSTR), ('State', wintypes.DWORD)]


class WTS_CLIENT_ADDRESS(Structure):
    """
    WTS_CLIENT_ADDRESS structure class.
    """
    _fields_ = [('AddressFamily', wintypes.DWORD), ('Address', c_byte * 20)]


WTSEnumerateSessions = wtsapi32.WTSEnumerateSessionsW
WTSEnumerateSessions.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, POINTER(POINTER(WTS_SESSION_INFO)), POINTER(wintypes.DWORD)]
WTSEnumerateSessions.restype = wintypes.BOOL
WTSQuerySessionInformation = wtsapi32.WTSQuerySessionInformationW
WTSQuerySessionInformation.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, c_int, POINTER(c_void_p), POINTER(wintypes.DWORD)]
WTSQuerySessionInformation.restype = wintypes.BOOL
WTSFreeMemory = wtsapi32.WTSFreeMemory
WTSFreeMemory.argtypes = [c_void_p]
WTSFreeMemory.restype = None
WTSDisconnectSession = wtsapi32.WTSDisconnectSession
WTSDisconnectSession.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL]
WTSDisconnectSession.restype = wintypes.BOOL
WTSLogoffSession = wtsapi32.WTSLogoffSession
WTSLogoffSession.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL]
WTSLogoffSession.restype = wintypes.BOOL


# ---------------------------------------------------------------------------
# Session enumeration
# ---------------------------------------------------------------------------

def _query_string(session_id, info_class):
    buf = c_void_p()
    size = wintypes.DWORD()
    ok = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session_id, info_class, byref(buf), byref(size))
    if not ok or not buf.value:
        return None
    try:
        return wstring_at(buf.value)
    finally:
        WTSFreeMemory(buf)


def _query_client_ip(session_id):
    buf = c_void_p()
    size = wintypes.DWORD()
    ok = WTSQuerySessionInformation(
        WTS_CURRENT_SERVER_HANDLE, session_id, WTS_INFO_CLIENT_ADDRESS, byref(buf), byref(size))
    if not ok or not buf.value:
        return None
    try:
        addr = cast(buf.value, POINTER(WTS_CLIENT_ADDRESS)).contents
        b = [x & 0xFF for x in addr.Address]
        if addr.AddressFamily == AF_INET:
            if b[2:6] == [0, 0, 0, 0]:
                return None
            return ".".join(str(x) for x in b[2:6])
        if addr.AddressFamily == AF_INET6:
            words = [(b[i] << 8) | b[i + 1] for i in range(2, 18, 2)]
            if not any(words):
                return None
            return ":".join("{:x}".format(w) for w in words)
        return None
    finally:
        WTSFreeMemory(buf)


def get_rdp_sessions():
    """
    Return a list of dicts for every session that has a remote client IP.
    """
    p_sessions = POINTER(WTS_SESSION_INFO)()
    count = wintypes.DWORD()
    ok = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, byref(p_sessions), byref(count))
    if not ok:
        raise WinError(get_last_error())
    sessions = []
    try:
        for i in range(count.value):
            s = p_sessions[i]
            ip = _query_client_ip(s.SessionId)
            if not ip:
                continue  # local/console sessions have no remote client IP.
            sessions.append({
                'session_id': s.SessionId,
                'station': s.pWinStationName or '',
                'user': _query_string(s.SessionId, WTS_INFO_USERNAME) or '',
                'client_ip': ip,
                'state': STATE_NAMES.get(s.State, str(s.State)),
            })
    finally:
        WTSFreeMemory(p_sessions)
    return sessions


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def disconnect_session(session_id, wait=True):
    """
    Drop the remote connection; the session keeps running. Returns True on success.
    :param session_id: int
    :param wait: bool
    :return: bool
    """
    ok = WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, session_id, wait)
    if not ok:
        raise WinError(get_last_error())
    return True


def logoff_session(session_id, wait=True):
    """
    End the session entirely (apps closed, unsaved work lost). Returns True on success.
    :param session_id: int
    :param wait: bool
    :return: bool
    """
    ok = WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, session_id, wait)
    if not ok:
        raise WinError(get_last_error())
    return True


def find_sessions_by_ip(sessions, ips):
    return [s for s in sessions if s['client_ip'] in set(ips)]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _is_admin():
    """
    :return: bool
    """
    try:
        return bool(IsUserAnAdmin())
    except Exception:
        return False


def _print_sessions(sessions):
    if not sessions:
        print('  No remote RDP sessions found.')
        return
    for s in sessions:
        print('  session {:>3}  {:<25}  {:<22}  {}'.format(
            s['session_id'], s['user'] or '(no user)', s['client_ip'], s['state']))


def main(argv=None):
    parser = ArgumentParser(description='Disconnect or log off RDP clients on this host by client IP.')
    parser.add_argument('ips', nargs='*', help='Client IP address(es) to act on')
    parser.add_argument("--list", action='store_true', help='List current RDP sessions and exit')
    parser.add_argument("--logoff", action='store_true', help='Log the session off instead of just disconnecting it')
    parser.add_argument("--dry-run", action='store_true', help='Show what would happen without changing anything')
    parser.add_argument("-y", "--yes", action='store_true', help='Skip the confirmation prompt')
    args = parser.parse_args(argv)
    sessions = get_rdp_sessions()
    if args.list or not args.ips:
        print('Current RDP sessions:')
        _print_sessions(sessions)
        if not args.ips:
            print("\nPass one or more client IPs to disconnect them "
                  "(add --logoff to log off instead).")
        return 0
    targets = find_sessions_by_ip(sessions, args.ips)
    matched_ips = {s['client_ip'] for s in targets}
    for ip in args.ips:
        if ip not in matched_ips:
            print('  No active session from {}'.format(ip))
    if not targets:
        print('Nothing to do.')
        return 1
    action = 'Log off' if args.logoff else 'Disconnect'
    print('\n{} the following session(s):'.format(action))
    _print_sessions(targets)
    if not args.dry_run and not _is_admin():
        print("\nWarning: not running as Administrator — the operation will likely "
              "fail with 'Access is denied'. Re-run from an elevated prompt.")
    if args.dry_run:
        print('\n[dry-run] No changes made.')
        return 0
    if not args.yes:
        reply = input('\nProceed to {} {} session(s)? [y/N] '.format(action.lower(), len(targets)))
        if reply.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 0
    act = logoff_session if args.logoff else disconnect_session
    failures = 0
    for s in targets:
        try:
            act(s['session_id'])
            print("  OK: session {} ({}) {}".format(
                s['session_id'], s['client_ip'], 'logged off' if args.logoff else 'disconnected'))
        except OSError as e:
            failures += 1
            print('  FAILED: session {} ({}): {}'.format(s['session_id'], s['client_ip'], e))
    return 1 if failures else 0


if __name__ == '__main__':
    exit(main())
