# MiniRDPBlocker

A lightweight, password-protected Windows utility that watches Remote Desktop (RDP)
sessions on the local host and automatically **disconnects** or **logs off** clients
that match a blocklist of IP addresses, CIDR ranges, IP ranges, or countries.

It is a defensive tool: it never reaches out and disconnects anything remotely — it
only acts on RDP sessions that are already connected to *this* machine, and it needs
to be run elevated (Administrator) to do so, since ending another user's session is a
privileged operation on Windows.

---

## How it works:

The project is four small, mostly-standalone modules:

| File               | Role                                                                                                                                                                                                                                                                                                                      |
|--------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `miniblocker.py`   | Entry point. CLI, SQLite-backed config/password/blocklist store, and the background scan loop.                                                                                                                                                                                                                            |
| `rdpdisconnect.py` | Thin `ctypes` wrapper around the Windows Terminal Services (WTS) API — enumerates RDP sessions and can disconnect/log them off by session ID.                                                                                                                                                                             |
| `hostutils.py`     | Regex helpers for validating and extracting IPs, CIDR ranges, IP ranges, and ports; also exposes `ipHosts()`, a generator of the client IPs currently connected over RDP.                                                                                                                                                 |
| `netgeo.py`        | Optional geolocation layer (`GeoGrabber`) used to resolve a client IP to a country when a **country** rule (not just an IP rule) is configured, and to download/refresh the offline databases it reads from (`--update_geodata`). Imported lazily — if it or its dependencies aren't available, IP-only rules still work. |

### Session lifecycle:

1. `rdpdisconnect.get_rdp_sessions()` enumerates active WTS sessions and returns each
   one's session ID, username, state, and remote client IP (via `WTSQuerySessionInformation`).
2. The blocker loop (`runBlocker` in `miniblocker.py`) polls this list every
   `interval` seconds (default `0.3s`).
3. For each session's client IP, it checks:
    - **IP rules** first (exact match against the blocklist), then
    - **Country rules**, if configured — resolving the IP's country via `netgeo.GeoGrabber` (with a small in-memory
      cache).
4. On a match, it calls `disconnect_session()` or `logoff_session()` (from `rdpdisconnect.py`)
   depending on the rule, subject to a 5-second cooldown per session to avoid hammering
   the same session repeatedly.
5. If logging is enabled, every match (and, optionally, every "seen" session) is written
   to a `connection_log` table for later review.

### Persistence:

The app's own state — password, settings, blocklist — lives in a small SQLite database:

```
%PROGRAMDATA%\MiniRDPBlocker\config.db
```

Three tables:

- **`config`** — key/value settings (password hash/salt/iterations, logging on/off, scan interval).
- **`hosts`** — the blocklist: each row is a host (`IP`/CIDR/range or country name), its `kind`,
  and whether it triggers `disconnect` and/or `logoff`.
- **`connection_log`** — a timestamped audit trail of sessions seen and actions taken.

Separately, the offline geo databases used for **country** rules live under `%APPDATA%\geodata\`
(a per-user location, unlike the machine-wide `%PROGRAMDATA%` above) — see the Geolocation
section below.

### Password protection:

The app is gated by a password before any config change or view is applied:

- On first run (either with or without arguments) you're prompted to **create** a password.
- The password itself is never stored — only a **PBKDF2-HMAC-SHA256** hash (200,000 iterations)
  with a random 16-byte salt, verified with a constant-time comparison (`hmac.compare_digest`).
- Launching with **no** action arguments skips the password prompt (once a password exists)
  and goes straight into the hidden background blocker — that's the "protected mode" the
  scheduled task runs under.

### Modes of operation:

**No arguments** → starts the background blocker:

- Ensures only one instance runs at a time (`CreateMutexW`).
- Hides its own console window (`ShowWindow(SW_HIDE)`).
- Loops forever, reloading config/rules from the DB every 3 seconds so CLI changes made
  elsewhere take effect live, without needing a restart.

**One or more arguments** → requires the password, then applies changes/views and exits.

### CLI reference:

```
python miniblocker.py                                  # start hidden blocker
python miniblocker.py --hosts 45.9.20.5 China           # block an IP and a country
python miniblocker.py --hosts 45.9.20.5 --enable_logoff_session
python miniblocker.py --remove_hosts China              # unblock
python miniblocker.py --show_hosts_actions              # view rules + settings
python miniblocker.py --enable_startup --enable_log     # autostart + logging
python miniblocker.py --change_password
python miniblocker.py --list_sessions                   # live sessions, no changes
python miniblocker.py --update_geodata                  # download the free offline geo DBs
python miniblocker.py --update_geodata sxgeo dbip        # just these providers
python miniblocker.py --update_geodata geoip2 --maxmind_license YOUR_KEY
python miniblocker.py --show_geodata                     # what's downloaded, and when
```

| Flag                                     | Purpose                                                                                                                                      |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `--db PATH`                              | Use a specific database file instead of the default.                                                                                         |
| `--hosts HOST [HOST ...]`                | Add IP/CIDR/range or country name(s) to the blocklist.                                                                                       |
| `--remove_hosts HOST [HOST ...]`         | Remove host(s)/country from the blocklist.                                                                                                   |
| `--enable_disconnect_session`            | New hosts get **disconnected** (default behavior).                                                                                           |
| `--enable_logoff_session`                | New hosts get **logged off** instead (stronger).                                                                                             |
| `--enable_startup` / `--disable_startup` | Register/remove an elevated logon scheduled task (falls back to the `HKCU\...\Run` registry key, unelevated, if `schtasks` isn't available). |
| `--enable_log` / `--disable_log`         | Turn the connection log table on/off.                                                                                                        |
| `--interval SECONDS`                     | Change the scan interval.                                                                                                                    |
| `--change_password`                      | Change the app password.                                                                                                                     |
| `--show_hosts` / `--show_hosts_actions`  | List the blocklist, optionally with actions + settings.                                                                                      |
| `--list_sessions`                        | Show current live RDP sessions and exit — no changes made.                                                                                   |
| `--update_geodata [PROVIDER ...]`        | Download/refresh the offline geo databases used for country rules. No names given = every free provider, plus any you supplied a key for.    |
| `--show_geodata`                         | Show which offline geo databases are downloaded, and when.                                                                                   |
| `--maxmind_license KEY`                  | MaxMind GeoLite2 license key, used by `--update_geodata`'s `GeoIP2` provider.                                                                |
| `--ip2location_token TOKEN`              | IP2Location download token, used by `--update_geodata`'s `IP2Location`/`IP2Proxy` providers.                                                 |

### Startup / autostart:

`--enable_startup` registers a Task Scheduler task (`schtasks /Create ... /RL HIGHEST`)
that runs `pythonw.exe miniblocker.py` at logon with elevated rights — needed because
disconnecting *other* users' sessions requires admin privileges, and a Task Scheduler
task can get that without a UAC prompt at logon. If `schtasks` is unavailable, it falls
back to the `HKCU` Run registry key (which will **not** be elevated).

### Rule matching (`hostutils.py`)

Rules can be:

- A single IP: `45.9.20.5`
- A CIDR block: `45.9.20.0/24`
- An IP range: `45.9.20.1 - 45.9.20.255`
- An IP with a port: `45.9.20.5:3389`
- A country name (anything that doesn't match the IP grammar above): `China`

`classifyHost()` decides `ip` vs `country` using the same regex grammar that
`isIpAddress()` / `ipList()` / `matchIp()` expose for validation and extraction elsewhere.

### Geolocation (`netgeo.py`)

`GeoGrabber.smartGeo()` merges results from multiple offline databases (IP2Location,
MaxMind GeoIP/GeoIP2, ip2nation, Sypex Geo) and online services (ip-api.com, ipapi,
ipstack, and many geocoder.com-style engines) into one dict, preferring offline/local
data and falling back to online lookups. `miniblocker.py` only calls the lightweight
path (`GeoGrabber(ip).smartGeo()["country_name"]`) and only when at least one country
rule is configured — if `netgeo` or its dependencies aren't installed, the import is
caught and country rules are simply skipped while IP rules continue to work.

#### Downloading the offline databases:

The offline databases don't ship with the project and aren't fetched automatically —
use `--update_geodata` to download them, and re-run it whenever you want a refresh
(nothing triggers this on a schedule on its own).

| Provider      | Key needed            | Format                     |
|---------------|-----------------------|----------------------------|
| `SxGeo`       | none                  | Sypex Geo `.dat`           |
| `DbIp`        | none                  | MaxMind-compatible `.mmdb` |
| `GeoIP`       | none                  | legacy MaxMind `.dat`      |
| `IP2Nation`   | none                  | `.zip`, read directly      |
| `GeoIP2`      | `--maxmind_license`   | MaxMind GeoLite2 `.mmdb`   |
| `IP2Location` | `--ip2location_token` | `.BIN`                     |
| `IP2Proxy`    | `--ip2location_token` | `.BIN`                     |

Running `--update_geodata` with no provider names attempts every key-free provider
plus any keyed one you supplied a matching flag for; a keyed provider you *didn't*
give a key for is skipped (reported, not treated as an error), and one file failing
to download doesn't stop the rest of the batch. Downloaded data lands under
`%APPDATA%\geodata\<provider>\` — `database\` holds the files the readers actually
use, `downloads\` the raw archives, and `datainfo.json` tracks what was last fetched
so a re-run only re-downloads what's actually changed. `--show_geodata` reports
what's currently on disk and when it was last updated.

Note that `netgeo.py` imports its full third-party dependency list at module load, so
those packages (see Requirements below) are needed even just to run
`--update_geodata`/`--show_geodata` — not only for the lookups themselves.

### `rdpdisconnect.py` as a standalone tool

This module also works as its own CLI for ad-hoc, one-off session management:

```
python rdpdisconnect.py --list                       # show sessions, change nothing
python rdpdisconnect.py 192.168.1.40                  # disconnect one IP
python rdpdisconnect.py 192.168.1.40 10.0.0.5 --logoff -y   # log off several IPs, no prompt
python rdpdisconnect.py 192.168.1.40 --dry-run        # show what would happen
```

---

## Requirements:

- **Windows only** (uses `ctypes`-based WTS and Win32 APIs — `wtsapi32.dll`, `kernel32.dll`, `user32.dll`,
  `shell32.dll`).
- Python 3 standard library covers `miniblocker.py`, `rdpdisconnect.py`, and `hostutils.py` with **no extra dependencies
  **.
- `netgeo.py` is optional and pulls in a long list of third-party geolocation packages
  (`geoip2`, `pygeoip`, `IP2Location`, `IP2Proxy`, `ipstack`, `geocoder`, `requests`, etc.).
  Needed if you plan to use **country**-based rules — and, since `netgeo.py` imports
  all of them at module load, also needed just to run `--update_geodata`/`--show_geodata`,
  even though downloading a database file doesn't itself use any of them.
- Must run **elevated** (Administrator) for disconnect/logoff actions to succeed;
  running unelevated will enumerate sessions fine but actions will fail with
  "Access is denied."

## Security notes:

- Passwords are never stored or logged in plaintext — only a salted PBKDF2 hash.
- The SQLite database lives under `%PROGRAMDATA%`, a machine-wide location — file
  permissions on that folder are what actually protects the DB from other local users,
  not the app itself.
- The tool only affects sessions on the local machine it runs on; its network attack
  surface is the optional outbound geolocation lookups, plus `--update_geodata`, which
  reaches out to whichever provider(s) you select (sypexgeo.net, db-ip.com, mailfud.org,
  ip2nation.com, maxmind.com, ip2location.com) to fetch their databases — only when you
  explicitly run that flag, never automatically.
