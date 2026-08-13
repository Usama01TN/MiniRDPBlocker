# -*- coding: utf-8 -*-
"""
Net geo scrapper.
"""
# Primary libs
from os import path, getenv, makedirs, listdir, rename, remove
from shutil import copyfile, rmtree
from json import load, dump, loads
from datetime import datetime
from glob import glob
import logging
import gzip
# Online geo libs.
from geocoder import arcgis, baidu, bing, canadapost, freegeoip, gaode, geolytica, geocodefarm, geonames, ottawa, \
    gisgraphy, google, here, ipinfo, komoot, locationiq, mapbox, mapquest, mapzen, maxmind, opencage, osm, tamu, tgos, \
    tomtom, uscensus, w3w, yahoo, yandex, ip
from geoip.xgeoip import GeoIp
from ipstack import GeoLookup
from ipapi import location
# Offline geo libs.
from pysyge.pysyge import MODE_BATCH, MODE_MEMORY
from IP2Proxy import IP2Proxy, IP2ProxyWebService
from geoip2.errors import AddressNotFoundError
from geoip2 import database, webservice
from pygeoip.const import MEMORY_CACHE
from IP2Location import IP2Location
from pysyge import GeoLocator
from pygeoip import GeoIP
# Archive extractor
from tarfile import open as open_gz, is_tarfile
from zipfile import ZipFile

# Url downloader
try:
    from urllib.request import urlretrieve, urlopen
except:
    from urllib import urlretrieve, urlopen

# ---------------------------------------------------------------------------
# TLS trust. A frozen (PyInstaller/Nuitka) exe usually has no usable CA
# bundle, so urlopen()/urlretrieve() fail with:
#     [SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate
# Set up a working trust source once, at import time, in this order:
#   1) truststore -- verify through the OS (Windows) certificate store, which
#      can also pull the missing intermediate certs these servers omit. It
#      patches ssl globally, so plain urlopen()/urlretrieve() just work.
#   2) certifi    -- fall back to a bundled Mozilla CA root file.
# Best-effort: if neither package is available we leave the default context
# alone (downloads may still fail, but importing netgeo never breaks).
# ---------------------------------------------------------------------------
try:
    import truststore as _truststore
    _truststore.inject_into_ssl()
except Exception:
    try:
        import ssl as _ssl
        import certifi as _certifi
        _CA_CTX = _ssl.create_default_context(cafile=_certifi.where())
        # urllib's urlopen()/urlretrieve() call this when no context is passed.
        _ssl._create_default_https_context = lambda *a, **k: _CA_CTX
    except Exception:
        pass

# HTTP client for REST geo services (ip-api.com). Falls back to urlopen
# so the module still works when the `requests` package is unavailable.
try:
    from requests import get as http_get
except ImportError:
    http_get = None

logging.disable(logging.ERROR)


class GeoGrabber(object):
    """
    GeoGrabber class.
    """

    def __init__(self, ipAdr=None):
        self.ip = ipAdr
        self._excludeKwd = ['-', 'UNAVAILABLE', '', 0, []]
        self.root_data = path.join(getenv('APPDATA'), "geodata/")
        self.offline = self.Offline(self)
        self.online = self.Online(self)

    class Offline(object):
        """
        Offline class.
        """
        # Providers that need a paid/registered token or license key, and
        # which update()/checkForUpdates() kwarg supplies it. Everything
        # else in _urlStruct works with no registration at all.
        _KEYED = {'IP2Location': 'token', 'IP2Proxy': 'token', 'GeoIP2': 'license'}

        def __init__(self, parent):
            self.ip = parent.ip
            self.parent = parent
            self._urlStruct = {
                'IP2Location': 'https://www.ip2location.com/download/?token={}&file={}',
                'IP2Proxy': 'https://www.ip2location.com/download/?token={}&file={}',
                'IP2Nation': 'http://www.ip2nation.com/{}.zip',
                'GeoIP': 'https://mailfud.org/geoip-legacy/{}.dat.gz',
                'GeoIP2': 'https://download.maxmind.com/app/geoip_download?license_key={}&edition_id={}&suffix=tar.gz',
                # Sypex Geo lite DBs -- free, no key/registration required.
                # https://sypexgeo.net/ru/download/
                'SxGeo': 'https://sypexgeo.net/files/{}.zip',
                # DB-IP Lite DBs -- free, no key/registration required, MaxMind
                # mmdb-compatible format, republished monthly (filename carries
                # the YYYY-MM tag, see checkForUpdates()). https://db-ip.com/db/
                'DbIp': 'https://download.db-ip.com/free/{}.mmdb.gz'}

        def isUpdated(self, pf=None, fn=None, key=None):
            """
            True if the local copy of `fn` (from provider `pf`) is already at
            least as large as what the remote currently serves, i.e. no
            download is needed. False -- the safe default -- the first time
            `pf` is downloaded, or if the remote can't be reached to check.
            """
            data_dir = path.join(self.parent.root_data, pf.lower())
            info_path = path.join(data_dir, 'datainfo.json')
            if not path.exists(info_path):
                return False
            try:
                load_info = load(open(info_path, 'r'))
                if fn not in load_info:
                    return False
                file_url = self._urlStruct[pf].format(key, fn) if key else self._urlStruct[pf].format(fn)
                remote_size = int(urlopen(file_url).info().get('Content-Length'))
                return remote_size <= load_info[fn]
            except Exception:
                return False

        def update(self, data_dict=None, providers=None, on_progress=None, **kwargs):
            """
            Download (and unpack) whichever offline geo databases need it.

            data_dict  : explicit {provider: [filenames]} to fetch, bypassing
                         the remote up-to-date check in checkForUpdates().
            providers  : when data_dict isn't given, restrict checkForUpdates()
                         to these provider names (default: every provider in
                         _urlStruct -- see PROVIDERS at module level).
            token      : IP2Location / IP2Proxy download token (kwarg).
            license    : MaxMind GeoLite2 license key (kwarg) -- free to
                         register for at maxmind.com/en/geolite2/signup.
            on_progress: optional callable(event, provider, filename, **info)
                         called for 'start' / 'ok' / 'error' events so a
                         caller can show progress; this method never prints.

            Free, no-key-required providers: SxGeo, DbIp, GeoIP, IP2Nation.
            :return: {'downloaded': [...], 'skipped': [...], 'failed': [...]}
                     -- lists of dicts describing what happened to each file.
            """

            def _emit(event, provider, filename=None, **info):
                if on_progress:
                    try:
                        on_progress(event, provider, filename, **info)
                    except Exception:
                        pass

            urls_key = {}
            if kwargs.get('token'):
                urls_key['IP2Location'] = kwargs['token']
                urls_key['IP2Proxy'] = kwargs['token']
            if kwargs.get('license'):
                urls_key['GeoIP2'] = kwargs['license']

            skippedProviders = []
            if not data_dict:
                data_dict, skippedProviders = self.checkForUpdates(providers=providers, **kwargs)

            result = {
                'downloaded': [],
                'skipped': [{'provider': p, 'reason': 'missing token/license'} for p in skippedProviders],
                'failed': [],
            }

            for it in data_dict:
                out_dir = path.join(self.parent.root_data, it.lower())
                down_dir = path.join(out_dir, 'downloads')
                db_dir = path.join(out_dir, 'database')
                info_path = path.join(out_dir, 'datainfo.json')
                file_log = {}
                if path.exists(info_path):
                    try:
                        file_log = load(open(info_path, 'r'))
                    except Exception:
                        file_log = {}
                for fn in data_dict[it]:
                    _emit('start', it, fn)
                    try:
                        down_url = self._urlStruct[it].format(urls_key[it], fn) if it in urls_key \
                            else self._urlStruct[it].format(fn)
                        fl_ext = '.gz' if down_url.lower().endswith('gz') else '.zip'
                        fl_name = path.join(down_dir, fn + fl_ext)
                        makedirs(down_dir, exist_ok=True)
                        urlretrieve(down_url, fl_name)
                        makedirs(db_dir, exist_ok=True)

                        if it == 'IP2Nation':
                            # geoip.xgeoip.GeoIp reads the .zip archive
                            # itself (not its unpacked contents) -- just
                            # place it where the reader expects it.
                            copyfile(fl_name, path.join(db_dir, fn + fl_ext))
                        elif fl_ext == '.zip':
                            ZipFile(fl_name, 'r').extractall(db_dir)
                        else:
                            isTar = False
                            try:
                                isTar = is_tarfile(fl_name)
                            except Exception:
                                isTar = False
                            if isTar:
                                # MaxMind's tar.gz unpacks into a dated
                                # subfolder, e.g. GeoLite2-City_20260101/ --
                                # hoist the payload up so the flat paths the
                                # readers use (GeoLite2-City.mmdb) exist.
                                open_gz(fl_name, 'r').extractall(db_dir)
                                self._flattenDated(db_dir, fn)
                            else:
                                # A plain single-file gzip (legacy GeoIP's
                                # *.dat.gz, DB-IP's *.mmdb.gz), not a tar --
                                # decompress it directly.
                                outName = fn + ('.mmdb' if it == 'DbIp' else '.dat')
                                with gzip.open(fl_name, 'rb') as _fin, \
                                        open(path.join(db_dir, outName), 'wb') as _fout:
                                    _fout.write(_fin.read())

                        # Record success only once the file is fully
                        # unpacked, so a failed extraction never gets
                        # remembered as "up to date" and skipped forever.
                        size = path.getsize(fl_name)
                        file_log[fn] = size
                        dump(file_log, open(info_path, 'w'))
                        result['downloaded'].append({'provider': it, 'file': fn, 'bytes': size})
                        _emit('ok', it, fn, bytes=size)
                    except Exception as e:
                        result['failed'].append({'provider': it, 'file': fn, 'error': str(e)})
                        _emit('error', it, fn, error=str(e))
            return result

        @staticmethod
        def _flattenDated(db_dir, fn):
            """
            MaxMind's tar.gz downloads wrap their payload in a dated
            subfolder (e.g. GeoLite2-City_20260101/GeoLite2-City.mmdb,
            alongside a COPYRIGHT/LICENSE/README.txt). Hoist anything whose
            name starts with `fn` up into db_dir itself so the flat paths
            the readers expect exist, then drop the now-empty subfolder.
            """
            for sub in glob(path.join(db_dir, fn + '_*')):
                if not path.isdir(sub):
                    continue
                for f in listdir(sub):
                    if f.startswith(fn):
                        target = path.join(db_dir, f)
                        if path.exists(target):
                            try:
                                remove(target)
                            except OSError:
                                pass
                        rename(path.join(sub, f), target)
                rmtree(sub, ignore_errors=True)

        def checkForUpdates(self, providers=None, **kwargs):
            """
            Compare local vs. remote file sizes for each offline geo database
            and report which ones need downloading.

            providers : which provider names to check (default: every
                        provider in _urlStruct). A provider in _KEYED whose
                        token/license kwarg wasn't supplied is left out of
                        the check entirely (rather than crashing trying to
                        build its URL) and comes back in `skipped`.
            :return: (data_dict, skipped) -- data_dict maps provider name ->
                     [filenames that need downloading]; skipped is a list of
                     provider names left out for lack of a token/license.
            """
            data_dict = {}
            # DB-IP republishes its lite DBs monthly under a YYYY-MM suffix,
            # e.g. dbip-city-lite-2026-01.mmdb.gz -- tag today's file names
            # with the current month (if last month's file 404s, pass an
            # explicit `data_dict` to update() instead of relying on this).
            dbIpTag = datetime.now().strftime('%Y-%m')
            FileCode = {
                'IP2Location': ['DB11LITEBIN', 'DB11LITECSV', 'DBASNLITE', 'DB11LITEBINIPV6', 'DB11LITECSVIPV6',
                                'DBASNLITEIPV6'],
                'IP2Proxy': ['PX11LITEBIN', 'PX11LITECSV', 'PX11LITEBINIPV6', 'PX11LITECSVIPV6'],
                'IP2Nation': ['ip2nation'], 'GeoIP': ['GeoIP', 'GeoIPASNum', 'GeoIPASNumv6', 'GeoIPCity', 'GeoIPCityv6',
                                                      'GeoIPISP', 'GeoIPOrg', 'GeoIPv6'],
                'GeoIP2': ['GeoLite2-ASN', 'GeoLite2-ASN-CSV', 'GeoLite2-City', 'GeoLite2-City-CSV',
                           'GeoLite2-Country', 'GeoLite2-Country-CSV'],
                # Free, no key needed -- country + city lite DBs.
                'SxGeo': ['SxGeo', 'SxGeoCity'],
                # Free, no key needed -- city/country/ASN lite DBs, mmdb format.
                'DbIp': ['dbip-city-lite-{}'.format(dbIpTag), 'dbip-country-lite-{}'.format(dbIpTag),
                         'dbip-asn-lite-{}'.format(dbIpTag)]}
            urls_key = {}
            if kwargs.get('token'):
                urls_key['IP2Location'] = kwargs['token']
                urls_key['IP2Proxy'] = kwargs['token']
            if kwargs.get('license'):
                urls_key['GeoIP2'] = kwargs['license']

            skipped = []
            for it in (providers or FileCode):
                if it not in FileCode:
                    continue
                if it in self._KEYED and it not in urls_key:
                    skipped.append(it)
                    continue
                for fn in FileCode[it]:
                    isUp = self.isUpdated(it, fn, urls_key[it]) if it in urls_key else self.isUpdated(it, fn)
                    if not isUp:
                        data_dict.setdefault(it, []).append(fn)
            return data_dict, skipped

        def IP2Location(self):
            return IP2Location(path.join(self.parent.root_data,
                                         'IP2Location/database/IP2LOCATION-LITE-DB11.BIN')).get_all(self.ip)

        def IP2Proxy(self):
            return IP2Proxy(path.join(self.parent.root_data,
                                      'IP2Proxy/database/IP2PROXY-LITE-PX11.BIN')).get_all(self.ip)

        def GeoIP(self, HAVE_COUNTRY=True, HAVE_CITY=True, HAVE_IPASNUM=True, HAVE_ISP=True, HAVE_ORG=True):
            dataPth = path.join(self.parent.root_data, 'geoip/database/')
            geoDict = {}
            if HAVE_COUNTRY:
                geoObject = GeoIP(path.join(dataPth, 'GeoIP.dat'), MEMORY_CACHE)
                geoDict.update({'id': geoObject.id_by_addr(self.ip),
                                'country_code': geoObject.country_code_by_addr(self.ip),
                                'country_name': geoObject.country_name_by_addr(self.ip)
                                })
            if HAVE_CITY:
                geoCityObject = GeoIP(path.join(dataPth, 'GeoIPCity.dat'), MEMORY_CACHE)
                geoDict.update({'record': geoCityObject.record_by_addr(self.ip),
                                'region': geoCityObject.region_by_addr(self.ip),
                                'time_zone': geoCityObject.time_zone_by_addr(self.ip)
                                })
            if HAVE_IPASNUM:
                geoDict['asn'] = GeoIP(path.join(dataPth, 'GeoIPASNum.dat'), MEMORY_CACHE).asn_by_addr(self.ip)
            if HAVE_ISP:
                geoDict['isp'] = GeoIP(path.join(dataPth, 'GeoIPISP.dat'), MEMORY_CACHE).isp_by_addr(self.ip)
            if HAVE_ORG:
                geoDict['org'] = GeoIP(path.join(dataPth, 'GeoIPOrg.dat'), MEMORY_CACHE).org_by_addr(self.ip)
            return geoDict

        def GeoIP2(self, HAVE_CITY=True, HAVE_COUNTRY=True, HAVE_ASN=True, HAVE_ANON_IP=False, HAVE_DOMAIN=False,
                   HAVE_ENTERPRISE=False, HAVE_ISP=False, HAVE_CONNECT_TYPE=False, **kwargs):
            dataPth = path.join(self.parent.root_data, 'geoip2/database/')
            geoDict = {}
            if HAVE_CITY:
                city = database.Reader(fileish=path.join(dataPth, 'GeoLite2-City.mmdb'), **kwargs).city(self.ip)
                geoDict.update(city.raw if hasattr(city, 'raw') else city.to_dict())
            if HAVE_COUNTRY:
                country = database.Reader(fileish=path.join(dataPth, 'GeoLite2-Country.mmdb'), **kwargs).country(
                    self.ip)
                geoDict.update(country.raw if hasattr(country, 'raw') else country.to_dict())
            if HAVE_ASN:
                dr = database.Reader(fileish=path.join(dataPth, 'GeoLite2-ASN.mmdb'), **kwargs).asn(self.ip)
                geoDict.update(dr.raw if hasattr(dr, 'raw') else dr.to_dict())
            if HAVE_ANON_IP:
                geoDict.update(database.Reader(
                    fileish=path.join(dataPth, 'GeoIP2-Anonymous-ip.mmdb'), **kwargs).anonymous_ip(self.ip))
            if HAVE_DOMAIN:
                geoDict.update(database.Reader(fileish=path.join(dataPth, 'GeoLite2-Domain.mmdb'),
                                               **kwargs).domain(self.ip))
            if HAVE_ENTERPRISE:
                geoDict.update(database.Reader(
                    fileish=path.join(dataPth, 'GeoLite2-Enterprise.mmdb'), **kwargs).enterprise(self.ip))
            if HAVE_ISP:
                geoDict.update(database.Reader(fileish=path.join(dataPth, 'GeoLite2-ISP.mmdb'), **kwargs).isp(self.ip))
            if HAVE_CONNECT_TYPE:
                geoDict.update(database.Reader(
                    fileish=path.join(dataPth, 'GeoLite2-Connection-Type.mmdb'), **kwargs).connection_type(self.ip))
            return geoDict

        def xgeoip(self, **kwargs):
            r = GeoIp(data_file=path.join(self.parent.root_data, "ip2nation/database/ip2nation.zip"), **kwargs)
            r.load_memory()
            return r.resolve(self.ip)

        def pysyge(self, HAVE_CITY=True, file_mode=MODE_BATCH | MODE_MEMORY):
            """
            Getting detailed information, including region info.
            Reads the Sypex Geo lite DB (https://sypexgeo.net/ru/download/)
            downloaded to <root_data>/sxgeo/database/ by update() -- see the
            'SxGeo' entry in _urlStruct / checkForUpdates().
            """
            dataPth = path.join(self.parent.root_data, 'sxgeo/database/')
            geoDict = GeoLocator(path.join(dataPth, 'SxGeo.dat'), file_mode).get_location(self.ip, detailed=True)
            if HAVE_CITY:
                geoDict.update(GeoLocator(path.join(dataPth, 'SxGeoCity.dat'),
                                          file_mode).get_location(self.ip, detailed=True))

            return geoDict

        @staticmethod
        def _latestDbIpFile(folder, kind):
            """
            Return the newest dbip-<kind>-lite-*.mmdb file in `folder` (kind is
            'city', 'country' or 'asn'), or None if none has been downloaded
            yet. DB-IP tags filenames with YYYY-MM, so a lexicographic sort
            also sorts them chronologically.
            """
            matches = sorted(glob(path.join(folder, 'dbip-{}-lite-*.mmdb'.format(kind))))
            return matches[-1] if matches else None

        def DbIp(self, HAVE_CITY=True, HAVE_COUNTRY=True, HAVE_ASN=True, **kwargs):
            """
            Read the locally downloaded DB-IP Lite database(s)
            (https://db-ip.com/db/) -- free, no key/registration required,
            MaxMind mmdb-compatible format, so the same geoip2.database
            reader used for GeoIP2() works here too. Expects files under
            <root_data>/dbip/database/ (populated by update(), see the
            'DbIp' entry in _urlStruct / checkForUpdates()).
            """
            dataPth = path.join(self.parent.root_data, 'dbip/database/')
            geoDict = {}
            if HAVE_CITY:
                f = self._latestDbIpFile(dataPth, 'city')
                if f:
                    city = database.Reader(fileish=f, **kwargs).city(self.ip)
                    geoDict.update(city.raw if hasattr(city, 'raw') else city.to_dict())
            if HAVE_COUNTRY:
                f = self._latestDbIpFile(dataPth, 'country')
                if f:
                    country = database.Reader(fileish=f, **kwargs).country(self.ip)
                    geoDict.update(country.raw if hasattr(country, 'raw') else country.to_dict())
            if HAVE_ASN:
                f = self._latestDbIpFile(dataPth, 'asn')
                if f:
                    asn = database.Reader(fileish=f, **kwargs).asn(self.ip)
                    geoDict.update(asn.raw if hasattr(asn, 'raw') else asn.to_dict())
            return geoDict

        def smartGeo(self, fast_mode=False):
            geoDict = {}
            i2loc = self.IP2Location()
            gip = self.GeoIP()
            dbip = {}
            if not fast_mode:
                try:
                    gip2 = self.GeoIP2()
                except AddressNotFoundError:
                    gip2 = {}
                x_gip = self.xgeoip()
                psg = self.pysyge()
                try:
                    dbip = self.DbIp()
                except AddressNotFoundError:
                    dbip = {}
                except Exception:
                    dbip = {}

            if not i2loc.country_short in self.parent._excludeKwd:
                geoDict['country_code'] = i2loc.country_short
            elif not fast_mode:
                try:
                    if gip['country_code']:
                        geoDict['country_code'] = gip['country_code']
                    elif gip2['country']['iso_code']:
                        geoDict['country_code'] = gip2['country']['iso_code']
                    elif x_gip.country_code:
                        geoDict['country_code'] = x_gip.country_code
                    else:
                        geoDict['country_code'] = psg['country_iso']
                except KeyError:
                    pass

            if not i2loc.country_short in self.parent._excludeKwd:
                geoDict['country_name'] = i2loc.country_long
            elif not fast_mode:
                try:
                    if gip['country_name']:
                        geoDict['country_name'] = gip['country_name']
                    elif gip2['country']['names']['en']:
                        geoDict['country_name'] = gip2['country']['names']['en']
                    elif gip2['registered_country']['names']['en']:
                        geoDict['country_name'] = gip2['registered_country']['names']['en']
                    elif x_gip.country:
                        geoDict['country_name'] = x_gip.country
                    else:
                        geoDict['country_name'] = psg['info']['country']['name_en']
                except KeyError:
                    pass

            try:
                if not i2loc.region in self.parent._excludeKwd:
                    geoDict['region'] = i2loc.region
                elif not fast_mode:
                    geoDict['region'] = psg['info']['region']['name_en']
            except KeyError:
                pass

            if not i2loc.city in self.parent._excludeKwd:
                geoDict['city'] = i2loc.city
            elif not fast_mode:
                try:
                    if gip['record']['city']:
                        geoDict['city'] = gip['record']['city']
                    elif gip2['city']['names']['en']:
                        geoDict['city'] = gip2['city']['names']['en']
                    else:
                        geoDict['city'] = psg['info']['city']['name_en']
                except (TypeError, KeyError):
                    pass

            if not fast_mode:
                try:
                    if gip2['location']['accuracy_radius']:
                        geoDict['accuracy_radius'] = gip2['location']['accuracy_radius']
                except (TypeError, KeyError):
                    pass

            if not i2loc.latitude in self.parent._excludeKwd:
                geoDict['latitude'] = i2loc.latitude
            elif not fast_mode:
                try:
                    if gip['record']['latitude']:
                        geoDict['latitude'] = gip['record']['latitude']
                    elif gip2['location']['latitude']:
                        geoDict['latitude'] = gip2['location']['latitude']
                    else:
                        geoDict['latitude'] = psg['info']['city']['lat']
                except (TypeError, KeyError):
                    pass

            if not i2loc.longitude in self.parent._excludeKwd:
                geoDict['longitude'] = i2loc.longitude
            elif not fast_mode:
                try:
                    if gip['record']['longitude']:
                        geoDict['longitude'] = gip['record']['longitude']
                    elif gip2['location']['longitude']:
                        geoDict['longitude'] = gip2['location']['longitude']
                    else:
                        geoDict['longitude'] = psg['info']['city']['lon']
                except (TypeError, KeyError):
                    pass

            if not i2loc.zipcode in self.parent._excludeKwd:
                geoDict['zipcode'] = i2loc.zipcode
            if not i2loc.timezone in self.parent._excludeKwd:
                geoDict['timezone'] = i2loc.timezone
            try:
                if gip['record']['dma_code']:
                    geoDict['dma_code'] = gip['record']['dma_code']
            except (TypeError, KeyError):
                pass
            try:
                if gip['record']['area_code']:
                    geoDict['area_code'] = gip['record']['area_code']
            except (TypeError, KeyError):
                pass
            try:
                if gip['record']['metro_code']:
                    geoDict['metro_code'] = gip['record']['metro_code']
            except (TypeError, KeyError):
                pass

            try:
                if gip['record']['postal_code']:
                    geoDict['postal_code'] = gip['record']['postal_code']
                elif not fast_mode:
                    geoDict['postal_code'] = gip2['postal']['code']
            except (TypeError, KeyError):
                pass

            try:
                if gip['record']['country_code3']:
                    geoDict['country_code3'] = gip['record']['country_code3']
            except (TypeError, KeyError):
                pass

            try:
                if gip['record']['continent']:
                    geoDict['continent'] = gip['record']['continent']
                elif not fast_mode:
                    geoDict['continent'] = gip2['continent']['code']
            except (TypeError, KeyError):
                pass

            try:
                if gip['record']['region_code']:
                    geoDict['region_code'] = gip['record']['region_code']
                elif not fast_mode:
                    if gip['region']['region_code']:
                        geoDict['region_code'] = gip['region']['region_code']
                    else:
                        geoDict['region_code'] = gip2['subdivisions'][0]['iso_code']
            except (TypeError, KeyError):
                pass

            try:
                if gip['time_zone']:
                    geoDict['time_zone_name'] = gip['time_zone']
                elif not fast_mode:
                    geoDict['time_zone_name'] = gip2['location']['time_zone']
            except KeyError:
                pass
            except (TypeError, KeyError):
                pass

            try:
                if gip['asn']:
                    geoDict['asn'] = gip['asn']
                elif not fast_mode and 'autonomous_system_number' in gip2 and 'autonomous_system_organization' in gip2:
                    geoDict['asn'] = '{} {}'.format(gip2['autonomous_system_number'],
                                                    gip2['autonomous_system_organization'])
            except (TypeError, KeyError):
                pass

            try:
                if gip['isp']:
                    geoDict['isp'] = gip['isp']
                elif not fast_mode and 'autonomous_system_organization' in gip2:
                    geoDict['isp'] = gip2['autonomous_system_organization']
            except (TypeError, KeyError):
                pass

            try:
                if gip['org']:
                    geoDict['org'] = gip['org']
                elif not fast_mode and 'autonomous_system_organization' in gip2:
                    geoDict['org'] = gip2['autonomous_system_organization']
            except (TypeError, KeyError):
                pass

            # DB-IP -- only fills gaps left by the sources above (setdefault),
            # never overwrites an already-resolved field. mmdb readers return
            # None (not KeyError) for an unresolved field, and None isn't in
            # _excludeKwd, so it's checked explicitly via _dbipOk() below.
            if dbip:
                def _dbipOk(v):
                    return v is not None and v not in self.parent._excludeKwd

                def _sub(d, key):
                    # Safe nested-dict lookup: a present-but-null key (mmdb
                    # readers use None, not KeyError, for unresolved fields)
                    # must not blow up the next .get() in the chain.
                    v = (d or {}).get(key)
                    return v if isinstance(v, dict) else {}

                country = _sub(dbip, 'country')
                v = country.get('iso_code')
                if _dbipOk(v):
                    geoDict.setdefault('country_code', v)
                v = _sub(country, 'names').get('en')
                if _dbipOk(v):
                    geoDict.setdefault('country_name', v)

                v = _sub(_sub(dbip, 'city'), 'names').get('en')
                if _dbipOk(v):
                    geoDict.setdefault('city', v)

                subs = dbip.get('subdivisions')
                if subs and isinstance(subs, list):
                    sub0 = subs[0] or {}
                    v = sub0.get('iso_code')
                    if _dbipOk(v):
                        geoDict.setdefault('region_code', v)
                    v = _sub(sub0, 'names').get('en')
                    if _dbipOk(v):
                        geoDict.setdefault('region', v)

                location = _sub(dbip, 'location')
                v = location.get('latitude')
                if _dbipOk(v):
                    geoDict.setdefault('latitude', v)
                v = location.get('longitude')
                if _dbipOk(v):
                    geoDict.setdefault('longitude', v)
                v = location.get('time_zone')
                if _dbipOk(v):
                    geoDict.setdefault('time_zone_name', v)

                v = _sub(dbip, 'continent').get('code')
                if _dbipOk(v):
                    geoDict.setdefault('continent', v)

                v = _sub(dbip, 'postal').get('code')
                if _dbipOk(v):
                    geoDict.setdefault('postal_code', v)

                asn_num = dbip.get('autonomous_system_number')
                asn_org = dbip.get('autonomous_system_organization')
                if asn_num is not None and _dbipOk(asn_org):
                    geoDict.setdefault('asn', '{} {}'.format(asn_num, asn_org))
                    geoDict.setdefault('isp', asn_org)

            return geoDict

    class Online(object):
        """
        Online class.
        """

        def __init__(self, parent):
            self.ip = parent.ip
            self.engine = 'default'
            self.parent = parent

        def geoplugin(self):
            """
            Tries to identify the physical location of an IP address using the Geoplugin geolocation web service
            (http://www.geoplugin.com/). There is no limit on lookups using this service.

            """

        def ipinfodb(self):
            """
            Tries to identify the physical location of an IP address using the IPInfoDB geolocation web service
            (http://ipinfodb.com/ip_location_api.php).

            There is no limit on requests to this service. However, the API key
            needs to be obtained through free registration for this service:
            <code>http://ipinfodb.com/login.php</code>

            """

        def virtualearth(self):
            """
            This script queries the Nmap registry for the GPS coordinates of targets stored
            by previous geolocation scripts and renders a Bing Map of markers representing the targets.

            The Bing Maps REST API has a limit of 100 markers, so if more coordinates are
            found, only the top 100 markers by number of IPs will be shown.

            Additional information for the Bing Maps REST Services API can be found at:
            - https://msdn.microsoft.com/en-us/library/ff701724.aspx

            Remark: You need to specify an API key, get one at https://www.bingmapsportal.com/.

            """

        def ip_api(self, fields=66846719, lang=None, **kwargs):
            """
            Tries to identify the physical location of an IP address using the
            ip-api.com geolocation web service (http://ip-api.com/).

            Free for non-commercial use and requires no API key, but the
            endpoint is rate limited to 45 requests per minute per source IP.

            The numeric ``fields`` value is a bitmask selecting which fields the
            service returns; the default (66846719) requests every field, e.g.
            ``{"status": "success", "continent": "Europe", "country": "France",
            "countryCode": "FR", "city": "Paris", "lat": 48.8575, ...}``.
            An optional ``lang`` code (e.g. 'en', 'fr', 'de') localises the
            country/region/city names.
            """
            url = "http://ip-api.com/json/{}?fields={}".format(self.ip, fields)
            if lang:
                url += "&lang={}".format(lang)
            if http_get is not None:
                return http_get(url, **kwargs).json()
            # Fallback when `requests` is not installed.
            return loads(urlopen(url).read().decode('utf-8'))

        def db_ip(self, api_key=None, **kwargs):
            """
            Tries to identify the physical location of an IP address using the
            DB-IP geolocation web service (https://db-ip.com/api/doc.php).

            With no `api_key`, uses the free, unauthenticated
            https://api.db-ip.com/v2/free/{ip} endpoint (no signup required,
            but rate limited to ~1 request/sec per source IP and returns a
            smaller field set). Pass an `api_key` from a paid DB-IP plan to
            use https://api.db-ip.com/v2/{api_key}/{ip} instead, which raises
            the rate limit and unlocks extra fields.

            Typical response: {"ipAddress": "1.1.1.1", "continentCode": "OC",
            "continentName": "Oceania", "countryCode": "AU",
            "countryName": "Australia", "stateProv": "Queensland",
            "city": "Brisbane", "latitude": -27.47, "longitude": 153.02, ...}
            """
            key = api_key or "free"
            url = "https://api.db-ip.com/v2/{}/{}".format(key, self.ip)
            if http_get is not None:
                return http_get(url, **kwargs).json()
            return loads(urlopen(url).read().decode('utf-8'))

        def grabGeo(self, engine=None, **kwargs):
            if engine:
                engine = engine.lower()
            else:
                engine = self.engine.lower()
            if engine == 'ArcGIS'.lower():
                session = arcgis(self.ip, **kwargs)
                return session.geojson
            elif engine == 'baidu':
                session = baidu(self.ip, **kwargs)
                return session.geojson
            elif engine == 'bing':
                session = bing(self.ip, **kwargs)
                return session.geojson
            elif engine == 'CanadaPost'.lower():
                session = canadapost(self.ip, **kwargs)
                return session.geojson
            elif engine == 'FreeGeoIP'.lower():
                session = freegeoip(self.ip, **kwargs)
                return session.geojson
            elif engine == 'gaode':
                session = gaode(self.ip, **kwargs)
                return session.geojson
            elif engine == 'geolytica':
                session = geolytica(self.ip, **kwargs)
                return session.geojson
            elif engine == 'GeocodeFarm'.lower():
                session = geocodefarm(self.ip, **kwargs)
                return session.geojson
            elif engine == 'GeoNames'.lower():
                session = geonames(self.ip, **kwargs)
                return session.geojson
            elif engine == 'GeoOttawa'.lower():
                session = ottawa(self.ip, **kwargs)
                return session.geojson
            elif engine == 'gisgraphy':
                session = gisgraphy(self.ip, **kwargs)
                return session.geojson
            elif engine == 'google':
                session = google(self.ip, **kwargs)
                return session.geojson
            elif engine == 'here':
                session = here(self.ip, **kwargs)
                return session.geojson
            elif engine == 'IPInfo'.lower():
                session = ipinfo(self.ip, **kwargs)
                return session.geojson
            elif engine == 'komoot':
                session = komoot(self.ip, **kwargs)
                return session.geojson
            elif engine == 'LocationIQ'.lower():
                session = locationiq(self.ip, **kwargs)
                return session.geojson
            elif engine == 'mapbox':
                session = mapbox(self.ip, **kwargs)
                return session.geojson
            elif engine == 'MapQuest'.lower():
                session = mapquest(self.ip, **kwargs)
                return session.geojson
            elif engine == 'mapzen':
                session = mapzen(self.ip, **kwargs)
                return session.geojson
            elif engine == 'MaxMind'.lower():
                """
                Tries to identify the physical location of an IP address using a Geolocation Maxmind database file
                (available from http://www.maxmind.com/app/ip-location). This script supports queries
                using all Maxmind databases that are supported by their API including the commercial ones.

                """
                session = maxmind(self.ip, **kwargs)
                return session.geojson
            elif engine == 'OpenCage'.lower():
                session = opencage(self.ip, **kwargs)
                return session.geojson
            elif engine == 'OpenStreetMap'.lower():
                session = osm(self.ip, **kwargs)
                return session.geojson
            elif engine == 'tamu':
                session = tamu(self.ip, **kwargs)
                return session.geojson
            elif engine == 'tgos':
                session = tgos(self.ip, **kwargs)
                return session.geojson
            elif engine == 'TomTom'.lower():
                session = tomtom(self.ip, **kwargs)
                return session.geojson
            elif engine == 'USCensus'.lower():
                session = uscensus(self.ip, **kwargs)
                return session.geojson
            elif engine == 'What3Words'.lower():
                session = w3w(self.ip, **kwargs)
                return session.geojson
            elif engine == 'yahoo':
                session = yahoo(self.ip, **kwargs)
                return session.geojson
            elif engine == 'yandex':
                session = yandex(self.ip, **kwargs)
                return session.geojson
            elif engine == 'ipapi':
                return location(self.ip, **kwargs)
            elif engine == 'ip-api' or engine == 'ipapicom':
                return self.ip_api(**kwargs)
            elif engine == 'db-ip' or engine == 'dbip':
                return self.db_ip(**kwargs)
            elif engine == 'IP2ProxyWebService'.lower():
                if not 'apikey' in kwargs:
                    kwargs['apikey'] = "S7YTOSACIX"
                return IP2ProxyWebService(kwargs['apikey'], "PX11", True).lookup(self.ip)
            elif engine == 'GeoIP2WebService'.lower():
                if not 'account_id' in kwargs:
                    kwargs['account_id'] = 798501
                if not 'licese_key' in kwargs:
                    kwargs['licese_key'] = 'FsO2gfaxQdZhBcsQ'
                with webservice.Client(*kwargs) as client:
                    city = client.city(self.ip)
                    insights = client.insights(self.ip)
                    country = client.country(self.ip)
                    return {city.raw if hasattr(city, 'raw') else city.to_dict(),
                            insights.raw if hasattr(insights, 'raw') else insights.to_dict(),
                            country.raw if hasattr(country, 'raw') else country.to_dict()}
            elif engine == 'ipstack':
                if not 'api_key' in kwargs:
                    kwargs['api_key'] = "d07db232d777da2a55242bb279c4c3b9"
                return GeoLookup(**kwargs).get_location(self.ip)
            else:
                session = ip(self.ip, **kwargs)
                return session.geojson

        def opengis(self):
            """
            This script queries the Nmap registry for the GPS coordinates of targets stored
            by previous geolocation scripts and produces a KML file of points representing the targets.

            """

        def smartGeo(self, HAVE_CANADA_POST=False, HAVE_IPSTACK=True, HAVE_IP2ProxyWebService=True, HAVE_IPAPI=True,
                     HAVE_IP_API=True, HAVE_DB_IP=True):
            geoDict = {}
            HAVE_DEFAULT = True
            try:
                defGeo = self.grabGeo('default')['features'][0]['properties']
            except:
                HAVE_DEFAULT = False
            if HAVE_CANADA_POST:
                try:
                    cndPst = self.grabGeo('CanadaPost')['features'][0]['properties']
                except:
                    HAVE_CANADA_POST = False
            if HAVE_IPSTACK:
                try:
                    ipStk = self.grabGeo('ipstack')
                except:
                    HAVE_IPSTACK = False
            if HAVE_IP2ProxyWebService:
                try:
                    i2pws = self.grabGeo('IP2ProxyWebService')
                except:
                    HAVE_IP2ProxyWebService = False
            if HAVE_IPAPI:
                try:
                    iApi = self.grabGeo('ipapi')
                except:
                    HAVE_IPAPI = False
            if HAVE_IP_API:
                try:
                    ipApiCom = self.grabGeo('ip-api')
                    # The service only returns geo fields on a successful lookup;
                    # private/reserved/invalid IPs come back as {"status": "fail"}.
                    if ipApiCom.get('status') != 'success':
                        HAVE_IP_API = False
                except:
                    HAVE_IP_API = False
            if HAVE_DB_IP:
                try:
                    dbIpCom = self.grabGeo('db-ip')
                    # Invalid/reserved IPs (or a dead free-tier rate limit)
                    # come back without a countryCode.
                    if not dbIpCom or not dbIpCom.get('countryCode'):
                        HAVE_DB_IP = False
                except:
                    HAVE_DB_IP = False
            # default
            if HAVE_DEFAULT:
                if not defGeo['address'] in self.parent._excludeKwd:
                    geoDict['address'] = defGeo['address']
                if not defGeo['city'] in self.parent._excludeKwd:
                    geoDict['city'] = defGeo['city']
                if not defGeo['country'] in self.parent._excludeKwd:
                    geoDict['country'] = defGeo['country']
                if not defGeo['state'] in self.parent._excludeKwd:
                    geoDict['state'] = defGeo['state']
                if 'hostname' in defGeo and not defGeo['hostname'] in self.parent._excludeKwd:
                    geoDict['hostname'] = defGeo['hostname']
                if not defGeo['lat'] in self.parent._excludeKwd:
                    geoDict['latitude'] = defGeo['lat']
                if not defGeo['lng'] in self.parent._excludeKwd:
                    geoDict['longitude'] = defGeo['lng']
                if not defGeo['org'] in self.parent._excludeKwd:
                    geoDict['org'] = defGeo['org']
                if 'postal' in defGeo and not defGeo['postal'] in self.parent._excludeKwd:
                    geoDict['postal'] = defGeo['postal']
                if not defGeo['raw']['region'] in self.parent._excludeKwd:
                    geoDict['region'] = defGeo['raw']['region']
                if not defGeo['raw']['loc'] in self.parent._excludeKwd:
                    geoDict['location'] = defGeo['raw']['loc']
                if not defGeo['raw']['timezone'] in self.parent._excludeKwd:
                    geoDict['timezone'] = defGeo['raw']['timezone']
            # CanadaPost
            if HAVE_CANADA_POST:
                if not cndPst['accuracy'] in self.parent._excludeKwd:
                    geoDict['accuracy'] = cndPst['accuracy']
                if not cndPst['domesticId'] in self.parent._excludeKwd:
                    geoDict['domestic_id'] = cndPst['domesticId']
                if not cndPst['housenumber'] in self.parent._excludeKwd:
                    geoDict['house_number'] = cndPst['housenumber']
                if not cndPst['label'] in self.parent._excludeKwd:
                    geoDict['label'] = cndPst['label']
                if not cndPst['quality'] in self.parent._excludeKwd:
                    geoDict['quality'] = cndPst['quality']
                if not cndPst['raw']['LanguageAlternatives'] in self.parent._excludeKwd:
                    geoDict['language_alternatives'] = cndPst['raw']['LanguageAlternatives']
                if not cndPst['raw']['Department'] in self.parent._excludeKwd:
                    geoDict['department'] = cndPst['raw']['Department']
                if not cndPst['raw']['Company'] in self.parent._excludeKwd:
                    geoDict['company'] = cndPst['raw']['Company']
                if not cndPst['raw']['SubBuilding'] in self.parent._excludeKwd:
                    geoDict['sub_building'] = cndPst['raw']['SubBuilding']
                if not cndPst['raw']['BuildingNumber'] in self.parent._excludeKwd:
                    geoDict['building_number'] = cndPst['raw']['BuildingNumber']
                if not cndPst['raw']['BuildingName'] in self.parent._excludeKwd:
                    geoDict['building_name'] = cndPst['raw']['BuildingName']
                if not cndPst['raw']['SecondaryStreet'] in self.parent._excludeKwd:
                    geoDict['secondary_street'] = cndPst['raw']['SecondaryStreet']
                if not cndPst['raw']['Street'] in self.parent._excludeKwd:
                    geoDict['street'] = cndPst['raw']['Street']
                if not cndPst['raw']['Neighbourhood'] in self.parent._excludeKwd:
                    geoDict['neighbourhood'] = cndPst['raw']['Neighbourhood']
                if not cndPst['raw']['District'] in self.parent._excludeKwd:
                    geoDict['district'] = cndPst['raw']['District']
                if not cndPst['raw']['Line1'] in self.parent._excludeKwd:
                    geoDict['line1'] = cndPst['raw']['Line1']
                if not cndPst['raw']['Line2'] in self.parent._excludeKwd:
                    geoDict['line2'] = cndPst['raw']['Line2']
                if not cndPst['raw']['Line3'] in self.parent._excludeKwd:
                    geoDict['line3'] = cndPst['raw']['Line3']
                if not cndPst['raw']['AdminAreaName'] in self.parent._excludeKwd:
                    geoDict['admin_area_name'] = cndPst['raw']['AdminAreaName']
                if not cndPst['raw']['AdminAreaCode'] in self.parent._excludeKwd:
                    geoDict['admin_area_code'] = cndPst['raw']['AdminAreaCode']
                if not cndPst['raw']['Province'] in self.parent._excludeKwd:
                    geoDict['province'] = cndPst['raw']['Province']
                if not cndPst['raw']['ProvinceName'] in self.parent._excludeKwd:
                    geoDict['province_name'] = cndPst['raw']['ProvinceName']
                if not cndPst['raw']['ProvinceCode'] in self.parent._excludeKwd:
                    geoDict['province_code'] = cndPst['raw']['ProvinceCode']
                if not cndPst['raw']['CountryIso2'] in self.parent._excludeKwd:
                    geoDict['country_iso2'] = cndPst['raw']['CountryIso2']
                if not cndPst['raw']['CountryIso3'] in self.parent._excludeKwd:
                    geoDict['country_iso3'] = cndPst['raw']['CountryIso3']
                if not cndPst['raw']['CountryIsoNumber'] in self.parent._excludeKwd:
                    geoDict['country_iso_number'] = cndPst['raw']['CountryIsoNumber']
                if not cndPst['raw']['Type'] in self.parent._excludeKwd:
                    geoDict['type'] = cndPst['raw']['Type']
                if not cndPst['raw']['DataLevel'] in self.parent._excludeKwd:
                    geoDict['data_level'] = cndPst['raw']['DataLevel']
            # ipstack
            if HAVE_IPSTACK:
                if not ipStk['continent_code'] in self.parent._excludeKwd:
                    geoDict['continent_code'] = ipStk['continent_code']
                if not ipStk['continent_name'] in self.parent._excludeKwd:
                    geoDict['continent_name'] = ipStk['continent_name']
                if not ipStk['region_code'] in self.parent._excludeKwd:
                    geoDict['region_code'] = ipStk['region_code']
                if not ipStk['region_name'] in self.parent._excludeKwd:
                    geoDict['region_name'] = ipStk['region_name']
                if not ipStk['zip'] in self.parent._excludeKwd:
                    geoDict['zip'] = ipStk['zip']
                if not ipStk['location']['capital'] in self.parent._excludeKwd:
                    geoDict['capital'] = ipStk['location']['capital']
                if not ipStk['location']['languages'][0]['name'] in self.parent._excludeKwd:
                    geoDict['language_name'] = ipStk['location']['languages'][0]['name']
                if not ipStk['location']['languages'][0]['native'] in self.parent._excludeKwd:
                    geoDict['language_native'] = ipStk['location']['languages'][0]['native']
                if not ipStk['location']['languages'][0]['code'] in self.parent._excludeKwd:
                    geoDict['language_code'] = ipStk['location']['languages'][0]['code']
            if HAVE_IP2ProxyWebService and i2pws:
                if not i2pws['isp'] in self.parent._excludeKwd:
                    geoDict['isp'] = i2pws['isp']
                if not i2pws['domain'] in self.parent._excludeKwd:
                    geoDict['domain'] = i2pws['domain']
                if not i2pws['usageType'] in self.parent._excludeKwd:
                    geoDict['usage_type'] = i2pws['usageType']
                if not i2pws['asn'] in self.parent._excludeKwd:
                    geoDict['asn'] = i2pws['asn']
                if not i2pws['as'] in self.parent._excludeKwd:
                    geoDict['as'] = i2pws['as']
                if not i2pws['lastSeen'] in self.parent._excludeKwd:
                    geoDict['last_seen'] = i2pws['lastSeen']
                if not i2pws['proxyType'] in self.parent._excludeKwd:
                    geoDict['proxy_type'] = i2pws['proxyType']
                if not i2pws['threat'] in self.parent._excludeKwd:
                    geoDict['threat'] = i2pws['threat']
                if not i2pws['provider'] in self.parent._excludeKwd:
                    geoDict['provider'] = i2pws['provider']
                if not i2pws['isProxy'] in self.parent._excludeKwd:
                    geoDict['is_proxy'] = i2pws['isProxy']
                if not i2pws['creditsConsumed'] in self.parent._excludeKwd:
                    geoDict['credits_consumed'] = i2pws['creditsConsumed']
            # ipapi
            if HAVE_IPAPI:
                if not iApi['utc_offset'] in self.parent._excludeKwd:
                    geoDict['utc_offset'] = iApi['utc_offset']
                if not iApi['country_calling_code'] in self.parent._excludeKwd:
                    geoDict['country_calling_code'] = iApi['country_calling_code']
                if not iApi['currency'] in self.parent._excludeKwd:
                    geoDict['currency'] = iApi['currency']
                if not iApi['currency_name'] in self.parent._excludeKwd:
                    geoDict['currency_name'] = iApi['currency_name']
                if not iApi['country_area'] in self.parent._excludeKwd:
                    geoDict['country_area'] = iApi['country_area']
                if not iApi['country_population'] in self.parent._excludeKwd:
                    geoDict['country_population'] = iApi['country_population']
                if not iApi['country_tld'] in self.parent._excludeKwd:
                    geoDict['country_tld'] = iApi['country_tld']
            # ip-api.com
            if HAVE_IP_API:
                # Shared keys -> setdefault so ip-api fills gaps left by the
                # other engines without overwriting their results.
                if not ipApiCom.get('country', '') in self.parent._excludeKwd:
                    geoDict.setdefault('country', ipApiCom['country'])
                if not ipApiCom.get('countryCode', '') in self.parent._excludeKwd:
                    geoDict.setdefault('country_code', ipApiCom['countryCode'])
                if not ipApiCom.get('continent', '') in self.parent._excludeKwd:
                    geoDict.setdefault('continent_name', ipApiCom['continent'])
                if not ipApiCom.get('continentCode', '') in self.parent._excludeKwd:
                    geoDict.setdefault('continent_code', ipApiCom['continentCode'])
                if not ipApiCom.get('region', '') in self.parent._excludeKwd:
                    geoDict.setdefault('region_code', ipApiCom['region'])
                if not ipApiCom.get('regionName', '') in self.parent._excludeKwd:
                    geoDict.setdefault('region_name', ipApiCom['regionName'])
                if not ipApiCom.get('city', '') in self.parent._excludeKwd:
                    geoDict.setdefault('city', ipApiCom['city'])
                if not ipApiCom.get('zip', '') in self.parent._excludeKwd:
                    geoDict.setdefault('zip', ipApiCom['zip'])
                if not ipApiCom.get('lat', '') in self.parent._excludeKwd:
                    geoDict.setdefault('latitude', ipApiCom['lat'])
                if not ipApiCom.get('lon', '') in self.parent._excludeKwd:
                    geoDict.setdefault('longitude', ipApiCom['lon'])
                if not ipApiCom.get('timezone', '') in self.parent._excludeKwd:
                    geoDict.setdefault('timezone', ipApiCom['timezone'])
                if not ipApiCom.get('currency', '') in self.parent._excludeKwd:
                    geoDict.setdefault('currency', ipApiCom['currency'])
                if not ipApiCom.get('isp', '') in self.parent._excludeKwd:
                    geoDict.setdefault('isp', ipApiCom['isp'])
                if not ipApiCom.get('org', '') in self.parent._excludeKwd:
                    geoDict.setdefault('org', ipApiCom['org'])
                if not ipApiCom.get('as', '') in self.parent._excludeKwd:
                    geoDict.setdefault('as', ipApiCom['as'])
                if not ipApiCom.get('reverse', '') in self.parent._excludeKwd:
                    geoDict.setdefault('hostname', ipApiCom['reverse'])
                # Fields unique to ip-api.com.
                if not ipApiCom.get('district', '') in self.parent._excludeKwd:
                    geoDict['district'] = ipApiCom['district']
                if not ipApiCom.get('asname', '') in self.parent._excludeKwd:
                    geoDict['asname'] = ipApiCom['asname']
                if not ipApiCom.get('reverse', '') in self.parent._excludeKwd:
                    geoDict['reverse'] = ipApiCom['reverse']
                if not ipApiCom.get('query', '') in self.parent._excludeKwd:
                    geoDict['query'] = ipApiCom['query']
                # Numeric/boolean fields: checked explicitly so legitimate 0 /
                # False values are not dropped by the _excludeKwd filter
                # (note False == 0, and 0 is in _excludeKwd).
                if ipApiCom.get('offset') is not None:
                    geoDict['utc_offset_seconds'] = ipApiCom['offset']
                if 'mobile' in ipApiCom:
                    geoDict['mobile'] = ipApiCom['mobile']
                if 'proxy' in ipApiCom:
                    geoDict['proxy'] = ipApiCom['proxy']
                if 'hosting' in ipApiCom:
                    geoDict['hosting'] = ipApiCom['hosting']
            # db-ip.com -- setdefault only, fills gaps without overwriting.
            # (DB-IP returns JSON `null` -- Python None -- for fields it can't
            # resolve; None isn't in _excludeKwd, so it's checked explicitly
            # here rather than being silently accepted like an empty string.)
            if HAVE_DB_IP:
                def _dbipOk(key):
                    v = dbIpCom.get(key)
                    return v is not None and v not in self.parent._excludeKwd

                if _dbipOk('countryName'):
                    geoDict.setdefault('country', dbIpCom['countryName'])
                if _dbipOk('countryCode'):
                    geoDict.setdefault('country_code', dbIpCom['countryCode'])
                if _dbipOk('continentName'):
                    geoDict.setdefault('continent_name', dbIpCom['continentName'])
                if _dbipOk('continentCode'):
                    geoDict.setdefault('continent_code', dbIpCom['continentCode'])
                if _dbipOk('stateProv'):
                    geoDict.setdefault('region_name', dbIpCom['stateProv'])
                if _dbipOk('city'):
                    geoDict.setdefault('city', dbIpCom['city'])
                if _dbipOk('zipCode'):
                    geoDict.setdefault('zip', dbIpCom['zipCode'])
                if _dbipOk('latitude'):
                    geoDict.setdefault('latitude', dbIpCom['latitude'])
                if _dbipOk('longitude'):
                    geoDict.setdefault('longitude', dbIpCom['longitude'])
                if _dbipOk('timeZone'):
                    geoDict.setdefault('timezone', dbIpCom['timeZone'])
            return geoDict

    def smartGeo(self):
        geoDict = {}
        try:
            geoDict.update(self.offline.smartGeo())
        except:
            pass
        geoDict.update(self.online.smartGeo())
        return geoDict


# ===========================================================================
# Module-level convenience wrappers for downloading/updating offline geo
# data -- this is what MiniRDPBlocker's --update_geodata / --show_geodata
# CLI flags call into, so the CLI layer doesn't need to reach into
# GeoGrabber().offline internals directly.
# ===========================================================================

# Canonical provider names, matching GeoGrabber.Offline._urlStruct's keys.
PROVIDERS = ('SxGeo', 'DbIp', 'GeoIP', 'IP2Nation', 'GeoIP2', 'IP2Location', 'IP2Proxy')


def normalizeProviders(names):
    """
    Map user-supplied provider names (case-insensitive, e.g. from a CLI
    argument) to their canonical form in PROVIDERS.
    :return: (resolved, unknown) -- resolved is the de-duplicated canonical
             names that matched; unknown is whatever didn't match anything.
    """
    lookup = dict((p.lower(), p) for p in PROVIDERS)
    resolved, unknown = [], []
    for n in names:
        canon = lookup.get(str(n).strip().lower())
        if canon:
            if canon not in resolved:
                resolved.append(canon)
        else:
            unknown.append(n)
    return resolved, unknown


def updateGeoData(providers=None, token=None, license=None, on_progress=None):
    """
    Download/refresh the offline geo databases used for country lookups.
    With no `providers`, every provider is considered: the free ones
    (SxGeo, DbIp, GeoIP, IP2Nation) are attempted, and the ones that need a
    key (IP2Location, IP2Proxy, GeoIP2) are attempted only if the matching
    `token`/`license` was supplied -- otherwise they come back in 'skipped'
    instead of failing.
    :return: {'downloaded': [...], 'skipped': [...], 'failed': [...]}
    """
    kwargs = {}
    if token:
        kwargs['token'] = token
    if license:
        kwargs['license'] = license
    return GeoGrabber().offline.update(providers=providers, on_progress=on_progress, **kwargs)


def geoDataStatus(providers=None):
    """
    Report what's currently on disk for each offline geo provider.
    :return: list of dicts (one per provider, in PROVIDERS order unless
             `providers` narrows it) with: provider, downloaded (bool),
             files (list of filenames under database/), total_bytes,
             updated_at (str timestamp of the last successful update, or
             None), needs_key (bool).
    """
    grabber = GeoGrabber()
    keyed = grabber.offline._KEYED
    rows = []
    for prov in (providers or PROVIDERS):
        out_dir = path.join(grabber.root_data, prov.lower())
        db_dir = path.join(out_dir, 'database')
        info_path = path.join(out_dir, 'datainfo.json')
        files = []
        if path.isdir(db_dir):
            for f in sorted(glob(path.join(db_dir, '*'))):
                if path.isfile(f):
                    files.append(path.basename(f))
        total = sum(path.getsize(path.join(db_dir, f)) for f in files) if files else 0
        updated_at = None
        if path.exists(info_path):
            updated_at = datetime.fromtimestamp(path.getmtime(info_path)).strftime('%Y-%m-%d %H:%M')
        rows.append({
            'provider': prov,
            'downloaded': bool(files),
            'files': files,
            'total_bytes': total,
            'updated_at': updated_at,
            'needs_key': prov in keyed,
        })
    return rows
