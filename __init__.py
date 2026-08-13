# -*- coding: utf-8 -*-
"""
Mini Blocker project for RDP.
"""
from os.path import dirname
from sys import path

if dirname(__file__) not in path:
    path.append(dirname(__file__))

try:
    from .rdpdisconnect import get_rdp_sessions, disconnect_session, logoff_session
    from .hostutils import buildIP
    from .netgeo import GeoGrabber
except:
    from rdpdisconnect import get_rdp_sessions, disconnect_session, logoff_session
    from hostutils import buildIP
    from netgeo import GeoGrabber

__version__ = '0.1.0'
__all__ = ['buildIP', 'GeoGrabber', 'get_rdp_sessions', 'disconnect_session', 'logoff_session']  # type: list[str]
