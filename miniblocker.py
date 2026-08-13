# -*- coding: utf-8 -*-
"""
MiniRDPBlocker
==============
Protect THIS Windows host by automatically dropping unwanted RDP sessions,
matched either by the client's IP address or by the country that IP
geolocates to.
Behaviour
---------
* Launched with NO action arguments:
      The background blocker starts and the console window is hidden.
      (On the very first run it first asks you to create a password.)
* Launched WITH one or more action arguments:
      You are asked for the password before any change is applied.
      On the very first run you are asked to CREATE a password instead.
Everything persistent -- the password (stored only as a salted PBKDF2
hash, never in plaintext), the settings, and the blocked IPs/countries --
lives in a small SQLite database under
%PROGRAMDATA%\\MiniRDPBlocker\\config.db.
Windows only. Disconnecting or logging off another user's session needs
Administrator rights, so run the blocker elevated (see --enable_startup,
which registers an elevated scheduled task).
Examples:
--------
    python miniblocker.py                                  # start hidden blocker
    python miniblocker.py --hosts 45.9.20.5 China          # block an IP and a country
    python miniblocker.py --hosts 45.9.20.5 --enable_logoff_session
    python miniblocker.py --remove_hosts China             # unblock
    python miniblocker.py --show_hosts_actions             # view rules + settings
    python miniblocker.py --enable_startup --enable_log     # autostart + logging
    python miniblocker.py --change_password
    python miniblocker.py --list_sessions                  # live sessions, no changes
    python miniblocker.py --update_geodata                 # download the free geo DBs
    python miniblocker.py --update_geodata sxgeo dbip       # only these providers
    python miniblocker.py --update_geodata geoip2 --maxmind_license YOUR_KEY
    python miniblocker.py --show_geodata                    # what's downloaded, and when
"""
from os.path import abspath, exists, dirname, join
from ctypes import WinDLL, windll, get_last_error
from os import environ, makedirs, urandom
from sys import executable, exit, path
from argparse import ArgumentParser
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from time import sleep, time
from getpass import getpass
from sqlite3 import connect
from re import compile

if dirname(__file__) not in path:
    path.append(dirname(__file__))

# --- imports that work both as a package and as loose scripts ---------------
try:
    from .rdpdisconnect import get_rdp_sessions, disconnect_session, logoff_session
    from .hostutils import buildIP
except Exception:
    from rdpdisconnect import get_rdp_sessions, disconnect_session, logoff_session
    from hostutils import buildIP

# GeoGrabber is only needed for COUNTRY rules. Keep it optional so the tool
# still runs (for IP rules) when netgeo or the network is unavailable.
try:
    from .netgeo import GeoGrabber, updateGeoData, geoDataStatus, normalizeProviders, PROVIDERS
except Exception:
    try:
        from netgeo import GeoGrabber, updateGeoData, geoDataStatus, normalizeProviders, PROVIDERS
    except Exception:
        GeoGrabber = None
        updateGeoData = None
        geoDataStatus = None
        normalizeProviders = None
        PROVIDERS = ()

APP_NAME = 'MiniRDPBlocker'
DEFAULT_INTERVAL = 0.3  # Seconds between session scans.
REFRESH_EVERY = 3.0  # Seconds between config/blocklist reloads.
ACTION_COOLDOWN = 5.0  # Seconds before acting on the same session again.
PBKDF2_ITERS = 200000
MIN_PW_LEN = 4
# A host string is treated as an IP if it fully matches the IP/CIDR/range grammar.
_HOST_IS_IP = compile(r'(?:' + buildIP + r')\Z')
# Windows Utils
IsUserAnAdmin = windll.shell32.IsUserAnAdmin
GetConsoleWindow = windll.kernel32.GetConsoleWindow
ShowWindow = windll.user32.ShowWindow


# ===========================================================================
# Storage (SQLite): password, config, hosts, connection log
# ===========================================================================
def defaultDbPath():
    """
    :return: str | unicode
    """
    base = environ.get('PROGRAMDATA') or dirname(abspath(__file__))
    folder = join(base, APP_NAME)
    try:
        makedirs(folder, exist_ok=True)
    except Exception:
        folder = dirname(abspath(__file__))
    return join(folder, 'config.db')


class Store(object):
    """
    Thin SQLite wrapper for the password, settings and blocklist.
    """

    def __init__(self, db_path):
        self.path = db_path
        self.conn = connect(db_path)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self._create()

    def _create(self):
        c = self.conn
        c.execute("""CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS hosts
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         host
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         kind
                         TEXT
                         NOT
                         NULL, -- 'ip' or 'country'
                         disconnect
                         INTEGER
                         NOT
                         NULL
                         DEFAULT
                         1,
                         logoff
                         INTEGER
                         NOT
                         NULL
                         DEFAULT
                         0,
                         created_at
                         TEXT
                         DEFAULT
                         CURRENT_TIMESTAMP
                     )""")
        c.execute("""CREATE TABLE IF NOT EXISTS connection_log
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         ts
                         TEXT
                         DEFAULT
                         CURRENT_TIMESTAMP,
                         session_id
                         INTEGER,
                         user
                         TEXT,
                         client_ip
                         TEXT,
                         country
                         TEXT,
                         state
                         TEXT,
                         action
                         TEXT
                     )""")
        c.commit()

    # ---- config (manual upsert -> works on any SQLite version) ----
    def getConfig(self, key, default=None):
        row = self.conn.execute('SELECT value FROM config WHERE key=?', (key,)).fetchone()
        return row[0] if row else default

    def setConfig(self, key, value):
        cur = self.conn.execute('UPDATE config SET value=? WHERE key=?', (str(value), key))
        if cur.rowcount == 0:
            self.conn.execute('INSERT INTO config(key,value) VALUES(?,?)', (key, str(value)))
        self.conn.commit()

    # ---- password (PBKDF2-HMAC-SHA256, salted; never stored in plaintext) ----
    def hasPassword(self):
        """
        :return: bool
        """
        return bool(self.getConfig('password_hash'))

    def setPassword(self, pw):
        salt = urandom(16)
        dk = pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, PBKDF2_ITERS)
        self.setConfig('password_salt', salt.hex())
        self.setConfig('password_hash', dk.hex())
        self.setConfig('password_iters', str(PBKDF2_ITERS))

    def verify(self, pw):
        """
        :param pw: str | unicode
        :return: bool
        """
        salt = self.getConfig('password_salt')
        want = self.getConfig('password_hash')
        iters = self.getConfig('password_iters')
        if not (salt and want and iters):
            return False
        dk = pbkdf2_hmac('sha256', pw.encode('utf-8'), bytes.fromhex(salt), int(iters))
        return compare_digest(dk.hex(), want)  # constant-time compare

    # ---- hosts ----
    def addHost(self, host, kind, disconnect, logoff):
        cur = self.conn.execute(
            "UPDATE hosts SET kind=?, disconnect=?, logoff=? WHERE host=?",
            (kind, int(disconnect), int(logoff), host))
        created = cur.rowcount == 0
        if created:
            self.conn.execute("INSERT INTO hosts(host,kind,disconnect,logoff) VALUES(?,?,?,?)",
                              (host, kind, int(disconnect), int(logoff)))
        self.conn.commit()
        return created

    def removeHost(self, host):
        """
        :param host: str | unicode
        :return: bool
        """
        cur = self.conn.execute('DELETE FROM hosts WHERE host=?', (host,))
        self.conn.commit()
        return cur.rowcount > 0

    def listHosts(self):
        """
        :return: list[str | unicode]
        """
        return self.conn.execute('SELECT host,kind,disconnect,logoff FROM hosts ORDER BY kind,host').fetchall()

    def getRules(self):
        """
        Return (ip_rules, country_rules) dicts for fast lookup in the blocker.
        """
        ip_rules, country_rules = {}, {}
        for host, kind, dc, lo in self.conn.execute('SELECT host,kind,disconnect,logoff FROM hosts'):
            rule = {'disconnect': bool(dc), 'logoff': bool(lo)}
            if kind == 'country':
                country_rules[host.strip().lower()] = rule
            else:
                ip_rules[host.strip()] = rule
        return ip_rules, country_rules

    # ---- log ----
    def log(self, session, country, action):
        self.conn.execute(
            'INSERT INTO connection_log(session_id,user,client_ip,country,state,action) VALUES(?,?,?,?,?,?)',
            (session.get('session_id'), session.get('user'),
             session.get('client_ip'), country or '', session.get('state'), action))
        self.conn.commit()


# ===========================================================================
# Small OS helpers (Windows)
# ===========================================================================
def classifyHost(host):
    """'
    ip' for an IP / CIDR / range / ip:port, otherwise 'country'.
    :param host: sstr | unicode
    :return: str | unicode
    """
    return 'ip' if _HOST_IS_IP.match(host.strip()) else 'country'


def isAdmin():
    """
    :return: bool
    """
    try:
        return bool(IsUserAnAdmin())
    except Exception:
        return False


def hideConsole():
    """
    Hide the console window (no effect when launched via pythonw.exe).
    :return:
    """
    try:
        hwnd = GetConsoleWindow()
        if hwnd:
            ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


def singleInstance(name='MiniRDPBlockerMutex'):
    """
    Return a truthy handle if we are the first instance, else None.
    :param name: str | unicode
    :return: bool
    """
    try:
        k32 = WinDLL('kernel32', use_last_error=True)
        handle = k32.CreateMutexW(None, False, name)
        if get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            return None
        return handle or True
    except Exception:
        return True  # Can't check -> assume we're fine.


def _pythonw():
    """
    :return: str | unicode
    """
    exe = executable or 'python.exe'
    if exe.lower().endswith('python.exe'):
        cand = exe[:-len('python.exe')] + 'pythonw.exe'
        if exists(cand):
            return cand
    return exe


def setStartup(enable):
    """
    Start at logon with highest privileges via a scheduled task.
    A Task Scheduler entry (not the HKCU Run key) is used because ending
    another user's RDP session needs elevation, and /RL HIGHEST gives the
    task that without a UAC prompt. Falls back to the registry if schtasks
    is unavailable.
    :param enable: bool
    :return: str | unicode
    """
    script = abspath(__file__)
    pyw = _pythonw()
    try:
        import subprocess
        if enable:
            cmd = ["schtasks", "/Create", "/TN", APP_NAME, "/TR", '"{}" "{}"'.format(pyw, script), "/SC",
                   "ONLOGON", "/RL", "HIGHEST", "/F"]
        else:
            cmd = ["schtasks", "/Delete", "/TN", APP_NAME, "/F"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            return "startup {} via scheduled task".format("enabled" if enable else "disabled")
    except Exception:
        pass
    return _setStartupRegistry(enable)


def _setStartupRegistry(enable):
    """
    :param enable: bool
    :return: str | unicode
    """
    try:
        from winreg import OpenKey, SetValueEx, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, HKEY_CURRENT_USER, \
            KEY_SET_VALUE, DeleteValue
    except Exception:
        return 'startup: not supported on this platform'
    runKey = r'Software\Microsoft\Windows\CurrentVersion\Run'
    try:
        if enable:
            cmd = '"{}" "{}"'.format(_pythonw(), abspath(__file__))
            with OpenKey(HKEY_CURRENT_USER, runKey, 0, KEY_SET_VALUE) as k:
                SetValueEx(k, APP_NAME, 0, REG_SZ, cmd)
            return 'startup enabled via registry (NOTE: not elevated)'
        with OpenKey(HKEY_CURRENT_USER, runKey, 0, KEY_SET_VALUE) as k:
            try:
                DeleteValue(k, APP_NAME)
            except FileNotFoundError:
                pass
        return 'startup disabled via registry'
    except Exception as e:
        return 'startup change failed: {}'.format(e)


# ===========================================================================
# The blocker
# ===========================================================================
_geoCache = {}


def _countryOf(ip):
    if ip in _geoCache:
        return _geoCache[ip]
    try:
        country = (GeoGrabber(ip).smartGeo() or {}).get('country_name') or ''
    except Exception:
        country = ''
    if len(_geoCache) > 4096:
        _geoCache.clear()
    _geoCache[ip] = country
    return country


def _float(v, default):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def runBlocker(store):
    if not isAdmin():
        # Visible only if a console still exists; harmless otherwise.
        print('WARNING: not elevated -- disconnect/logoff will fail. Run as Administrator.')
    ipRules, country_rules = store.getRules()
    logEnabled = store.getConfig('enable_log', '0') == '1'
    interval = _float(store.getConfig('interval'), DEFAULT_INTERVAL)
    lastRefresh = 0.0
    loggedSeen = set()  # (session_id, ip) already logged as 'seen'
    lastActed = {}  # session_id -> ts of last action (cooldown)
    while True:
        now = time()
        # Periodically reload config + rules so CLI changes take effect live.
        if now - lastRefresh >= REFRESH_EVERY:
            ipRules, country_rules = store.getRules()
            logEnabled = store.getConfig('enable_log', '0') == '1'
            interval = _float(store.getConfig('interval'), DEFAULT_INTERVAL)
            lastRefresh = now
        needCountry = bool(country_rules) and GeoGrabber is not None
        try:
            sessions = get_rdp_sessions()
        except Exception:
            sessions = []
        for s in sessions:
            ip = (s.get('client_ip') or '').strip()
            if not ip:
                continue
            rule = ipRules.get(ip)
            country = ''
            if rule is None and needCountry:
                country = _countryOf(ip)
                if country:
                    rule = country_rules.get(country.lower())
            if rule:
                sid = s['session_id']
                if now - lastActed.get(sid, 0.0) >= ACTION_COOLDOWN:
                    action = 'match(no-action)'
                    try:
                        if rule['logoff']:
                            logoff_session(sid)
                            action = 'logoff'
                        elif rule['disconnect']:
                            disconnect_session(sid)
                            action = 'disconnect'
                    except Exception as e:
                        action = 'error: {}'.format(e)
                    lastActed[sid] = now
                    if logEnabled:
                        store.log(s, country, action)
                continue  # matched -> don't also log as 'seen'
            if logEnabled:
                key = (s.get('session_id'), ip)
                if key not in loggedSeen:  # log each session once, not every tick
                    loggedSeen.add(key)
                    store.log(s, country, 'seen')
        sleep(interval)


# ===========================================================================
# Password prompts
# ===========================================================================
def createPassword(store):
    print('First run -- create a password for {}.'.format(APP_NAME))
    while True:
        p1 = getpass('New password: ')
        if len(p1) < MIN_PW_LEN:
            print("  Too short (min {} characters).".format(MIN_PW_LEN))
            continue
        if p1 != getpass('Confirm password: '):
            print('  Passwords do not match, try again.')
            continue
        store.setPassword(p1)
        print("Password saved.\n")
        return


def authenticate(store, attempts=3):
    for i in range(attempts):
        if store.verify(getpass('Password: ')):
            return True
        left = attempts - i - 1
        if left:
            print('  Incorrect. {} attempt(s) left.'.format(left))
    return False


# ===========================================================================
# CLI
# ===========================================================================
def buildParser():
    """
    :return: ArgumentParser
    """
    p = ArgumentParser(prog=APP_NAME, description='Automatically disconnect/log off RDP clients by IP or country.',
                       epilog='Run with no action arguments to start the hidden background blocker.')
    p.add_argument('--db', metavar='PATH', help='Use a specific database file.')
    p.add_argument('--hosts', nargs='+', metavar='HOST',
                   help='Add IP/CIDR/range or Country name(s) to the blocklist.')
    p.add_argument('--remove_hosts', nargs='+', metavar='HOST',
                   help='Remove host(s)/country from the blocklist.')
    p.add_argument('--enable_disconnect_session', action='store_true',
                   help='For hosts being added: DISCONNECT them (this is the default).')
    p.add_argument('--enable_logoff_session', action='store_true',
                   help='For hosts being added: LOG OFF them (stronger than disconnect).')
    p.add_argument('--enable_startup', action='store_true',
                   help='Start with Windows at logon (elevated scheduled task).')
    p.add_argument('--disable_startup', action='store_true',
                   help='Do not start with Windows.')
    p.add_argument('--enable_log', action='store_true',
                   help='Log all connections to the database.')
    p.add_argument('--disable_log', action='store_true',
                   help='Stop logging connections.')
    p.add_argument('--interval', type=float, metavar='SECONDS',
                   help='Seconds between scans (saved to config).')
    p.add_argument('--change_password', action='store_true',
                   help='Change the app password.')
    p.add_argument('--show_hosts', action='store_true',
                   help='Show all blocked hosts.')
    p.add_argument('--show_hosts_actions', action='store_true',
                   help='Show all blocked hosts with their actions and current settings.')
    p.add_argument('--list_sessions', action='store_true',
                   help='Show current live RDP sessions and exit.')
    geoProviderHelp = ('Providers: {} (default: every free one, plus any you gave a key for).'.format(
        ', '.join(PROVIDERS)) if PROVIDERS else "(netgeo module or its dependencies aren't installed.)")
    p.add_argument('--update_geodata', nargs='*', metavar='PROVIDER',
                   help='Download/refresh the offline geo databases used for country rules. ' + geoProviderHelp)
    p.add_argument('--show_geodata', action='store_true',
                   help='Show which offline geo databases are downloaded, and when.')
    p.add_argument('--maxmind_license', metavar='KEY',
                   help="MaxMind GeoLite2 license key, for --update_geodata's GeoIP2 provider.")
    p.add_argument('--ip2location_token', metavar='TOKEN',
                   help="IP2Location download token, for --update_geodata's IP2Location/IP2Proxy providers.")
    return p


def _hasAction(a):
    """True if any config-changing / viewing argument was supplied."""
    return any([
        a.hosts, a.remove_hosts, a.enable_disconnect_session, a.enable_logoff_session,
        a.enable_startup, a.disable_startup, a.enable_log, a.disable_log,
        a.change_password, a.show_hosts, a.show_hosts_actions, a.list_sessions,
        a.interval is not None, a.update_geodata is not None, a.show_geodata])


def applyActions(store, a, just_created):
    # --- settings ---
    if a.enable_startup:
        print(setStartup(True))
    if a.disable_startup:
        print(setStartup(False))
    if a.enable_log:
        store.setConfig('enable_log', '1')
        print('logging: enabled')
    if a.disable_log:
        store.setConfig('enable_log', '0')
        print('logging: disabled')
    if a.interval is not None:
        store.setConfig('interval', str(a.interval))
        print('scan interval: {}s'.format(a.interval))
    # --- password change (skip if we just created one this run) ---
    if a.change_password and not just_created:
        print('Change password:')
        createPassword(store)
    # --- add hosts ---
    if a.hosts:
        disconnect = a.enable_disconnect_session or not a.enable_logoff_session
        logoff = a.enable_logoff_session
        for h in a.hosts:
            h = h.strip()
            if not h:
                continue
            kind = classifyHost(h)
            created = store.addHost(h, kind, disconnect, logoff)
            act = 'logoff' if logoff else ('disconnect' if disconnect else 'none')
            print('  {} {} [{}] -> {}'.format('added' if created else 'updated', h, kind, act))
    # --- remove hosts ---
    if a.remove_hosts:
        for h in a.remove_hosts:
            h = h.strip()
            ok = store.removeHost(h)
            print('  {} {}'.format('removed' if ok else 'not found', h))
    # --- views ---
    if a.show_hosts or a.show_hosts_actions:
        rows = store.listHosts()
        if not rows:
            print('No hosts in the blocklist.')
        else:
            print('Blocked hosts:')
            for host, kind, dc, lo in rows:
                if a.show_hosts_actions:
                    act = 'logoff' if lo else ('disconnect' if dc else 'none')
                    print('  {:<24} {:<8} {}'.format(host, kind, act))
                else:
                    print('  {:<24} {}'.format(host, kind))
        if a.show_hosts_actions:
            print('\nSettings:')
            print('  logging       : {}'.format('on' if store.getConfig('enable_log', '0') == '1' else 'off'))
            print('  scan interval : {}s'.format(store.getConfig('interval', str(DEFAULT_INTERVAL))))
            print('  database      : {}'.format(store.path))
    if a.list_sessions:
        try:
            sessions = get_rdp_sessions()
        except Exception as e:
            print('Could not read sessions: {}'.format(e))
            sessions = []
        if not sessions:
            print('No remote RDP sessions.')
        else:
            print('Current RDP sessions:')
            for s in sessions:
                print('  session {:>3}  {:<22} {:<16} {}'.format(
                    s['session_id'], s.get('user') or '(no user)', s['client_ip'], s['state']))
    # --- offline geo database update ---
    if a.update_geodata is not None:
        if updateGeoData is None:
            print("Can't update geo data: the netgeo module (or one of its dependencies) isn't available.")
        else:
            providers = None
            proceed = True
            if a.update_geodata:
                providers, unknown = normalizeProviders(a.update_geodata)
                if unknown:
                    print('  unknown provider(s): {} -- choices: {}'.format(', '.join(unknown), ', '.join(PROVIDERS)))
                proceed = bool(providers)
            if proceed:
                def _onProgress(event, provider, filename=None, **info):
                    if event == 'start':
                        print('  {:<12} {:<24} ...'.format(provider, filename or ''))
                    elif event == 'ok':
                        print('ok ({:.1f} KB)'.format(info.get('bytes', 0) / 1024.0))
                    elif event == 'error':
                        print('FAILED: {}'.format(info.get('error', '')))

                print('Updating geo data ...')
                result = updateGeoData(
                    providers=providers, token=a.ip2location_token, license=a.maxmind_license, on_progress=_onProgress)
                for item in result['skipped']:
                    print('  {:<12} skipped ({})'.format(item['provider'], item['reason']))
                print('Done: {} downloaded, {} failed.'.format(len(result['downloaded']), len(result['failed'])))
    # --- offline geo database status ---
    if a.show_geodata:
        if geoDataStatus is None:
            print("Can't show geo data: the netgeo module (or one of its dependencies) isn't available.")
        else:
            print('Offline geo databases:')
            for r in geoDataStatus():
                if r['downloaded']:
                    print('  {:<12} {} file(s), {:.1f} MB, updated {}'.format(
                        r['provider'], len(r['files']), r['total_bytes'] / 1e6, r['updated_at'] or 'unknown'))
                else:
                    note = '  (needs --maxmind_license/--ip2location_token)' if r['needs_key'] else ''
                    print('  {:<12} not downloaded{}'.format(r['provider'], note))


def main(argv=None):
    args = buildParser().parse_args(argv)
    store = Store(args.db or defaultDbPath())
    # No action arguments -> run the hidden background blocker.
    if not _hasAction(args):
        if not store.hasPassword():
            createPassword(store)  # needs a visible console
        guard = singleInstance()
        if guard is None:
            print('Already running -- exiting.')
            return 0
        print('Starting {} ... (this window will hide)'.format(APP_NAME))
        hideConsole()
        try:
            runBlocker(store)
        except KeyboardInterrupt:
            pass
        return 0
    # Action arguments -> require the password (create it on first run).
    justCreated = False
    if not store.hasPassword():
        createPassword(store)
        justCreated = True
    elif not authenticate(store):
        print('Access denied.')
        return 1
    applyActions(store, args, justCreated)
    return 0


if __name__ == "__main__":
    exit(main())
