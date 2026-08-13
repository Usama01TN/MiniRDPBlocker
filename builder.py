#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
builder.py
============
Interactive/CLI builder that packages the MiniRDPBlocker project
(miniblocker.py + rdpdisconnect.py + hostutils.py + netgeo.py) into a single,
compressed, standalone Windows .exe using either PyInstaller or Nuitka.
Must be run on WINDOWS with a Python interpreter matching the target
architecture (building a Windows exe on Linux/macOS is not supported by
either tool in --onefile mode).
Usage:
-----
Interactive (asks which backend to use):
    python builder.py
Non-interactive:
    python builder.py --tool pyinstaller
    python builder.py --tool nuitka --no-console
    python builder.py --tool nuitka --upx --icon app.ico
Options:
-------
    --tool {pyinstaller,nuitka}   Skip the interactive prompt.
    --entry PATH                  Entry script (default: miniblocker.py).
    --name NAME                   Output exe base name (default: MiniRDPBlocker).
    --source-dir PATH             Folder containing the 4 project .py files
                                   (default: same folder as this script).
    --dist-dir PATH               Where the final exe is placed (default: ./dist).
    --icon PATH                   Optional .ico file for the exe.
    --console                     Build a console app (DEFAULT). Required for the
                                   CLI: it is how the exe prints output and reads
                                   the password prompt.
    --no-console / --windowed     Build a GUI/no-console app. WARNING: the tool
                                   can then neither print nor prompt for a
                                   password -- only use this if you know you want
                                   a purely silent background binary.
    --no-upx                      Disable UPX binary compression even if available.
    --skip-install                Don't auto pip-install the build backend.
    --yes / -y                    Don't ask for confirmation before building.
What it does:
------------
1. Verifies you're on Windows and that all 4 project files are present.
2. Installs the chosen backend (PyInstaller or Nuitka) via pip if missing.
3. Downloads/locates UPX for extra compression when available (optional,
   never a hard failure -- both tools work fine without it).
4. Runs a --onefile build tuned for small size:
     - PyInstaller: --onefile --strip --upx-dir=... --exclude common
       unneeded stdlib/test modules, --console by default (--windowed only
       when --no-console is passed).
     - Nuitka: --onefile --lto=yes --standalone, a normal console by default
       (--windows-console-mode=disable only when --no-console is passed),
       --remove-output, plugin auto-detection disabled
       for heavy optional deps that miniblocker only imports lazily.
5. Copies the final .exe into --dist-dir and prints its size.
Notes on size/optimization:
---------------------------
* netgeo.py imports a long list of optional third-party geolocation
  packages (geoip2, pygeoip, IP2Location, IP2Proxy, ipstack, geocoder...).
  If those aren't installed, PyInstaller/Nuitka can't bundle them either --
  which is fine, since miniblocker.py already treats a failed `netgeo`
  import as 'country rules unavailable' and keeps working for IP rules.
  Installing only the subset of geo packages you actually use (or none at
  all) keeps the executable meaningfully smaller.
* UPX (https://upx.github.io/) is optional but often shrinks the final exe
  by 40-60%% with no runtime cost beyond a slightly slower first launch
  (self-decompression). Point --upx-dir at it, or let this script try to
  find `upx`/`upx.exe` on PATH automatically.
"""
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from os.path import dirname, abspath, join, getsize, isfile
from sys import executable, exit, platform
from os import getcwd, makedirs, name
from sysconfig import get_platform
from pip import _internal
from shutil import move

try:
    from shutil import which
except:
    from os import pathsep, environ, access, X_OK
    from os.path import split


    def which(filename):
        """
        Locate an executable on PATH.
        :param filename: str | unicode
        :return: str | unicode | None
        """

        def isExecutable(pth):
            """
            :param pth: str | unicode
            :return: bool
            """
            return isfile(pth) and access(pth, X_OK)

        path, _ = split(filename)
        if path:
            if isExecutable(filename):
                return filename
        else:
            for directory in environ.get('PATH', '').split(pathsep):
                fullPath = join(directory, filename)
                if isExecutable(fullPath):
                    return fullPath
        exts = environ.get('PATHEXT', '').split(pathsep)
        for directory in environ.get('PATH', '').split(pathsep):
            for ext in [''] + exts:
                fullPath = join(directory, filename + ext)
                if isfile(fullPath) and access(fullPath, X_OK):
                    return fullPath
        return None

try:
    from subprocess import run
except:
    from subprocess import Popen, call, PIPE


    class _CompletedProcess(object):
        """
        Minimal subprocess.CompletedProcess shim.
        """

        def __init__(self, args, returncode, stdout=None, stderr=None):
            self.args = args
            self.returncode = returncode
            self.stdout = stdout or ''
            self.stderr = stderr or ''


    def run(cmd, cwd=None, env=None, capture_output=False, text=True):
        """
        Python shim for subprocess.run(capture_output=...).
        """
        if capture_output:
            proc = Popen(cmd, cwd=cwd, env=env, stdout=PIPE, stderr=PIPE)
            stdoutBytes, stderrBytes = proc.communicate()
            if text:
                stdout = stdoutBytes.decode('utf-8', errors='replace')
                stderr = stderrBytes.decode('utf-8', errors='replace')
            else:
                stdout, stderr = stdoutBytes, stderrBytes
            return _CompletedProcess(cmd, proc.returncode, stdout, stderr)
        return _CompletedProcess(cmd, call(cmd, cwd=cwd, env=env))

REQUIRED_FILES = ['miniblocker.py', 'rdpdisconnect.py', 'hostutils.py', 'netgeo.py']
# Heavy stdlib modules never needed by this project -- excluding them from
# PyInstaller's analysis trims real size off the bundle.
PYINSTALLER_EXCLUDES = ['tkinter', 'unittest', 'pydoc', 'doctest', 'test', 'lib2to3', 'curses', 'idlelib', 'turtledemo']


def die(msg, code=1):
    """
    :param msg: str | unicode
    :param code: int
    :return:
    """
    print('ERROR: {}'.format(msg))
    exit(code)


def haveModule(mod):
    """
    :param mod: str | unicode
    :return: bool
    """
    try:
        __import__(mod)
        return True
    except Exception:
        return False


def pipInstall(pkgs, skip_install):
    missing = [p for p in pkgs if not haveModule(p.split('==')[0].replace('-', '_'))]
    if not missing:
        return
    if skip_install:
        die('Missing required package(s) {} and --skip-install was set.'.format(missing))
    _internal.main(['install', '--upgrade'] + missing)


def findUpx():
    """
    :return: str | unicode | None
    """
    for candidate in ('upx', 'upx.exe'):
        path = which(candidate)
        if path:
            return dirname(path)
    return None


def checkWindows():
    """
    :return:
    """
    if name != 'nt' and platform != 'win32':
        print(
            'WARNING: this does not look like Windows (os.name={!r}, '
            'sys.platform={!r}). PyInstaller/Nuitka --onefile can only '
            'produce a native Windows .exe when actually run ON Windows '
            '(no cross-compiling from Linux/macOS). The build below will '
            'very likely fail.'.format(name, platform))


def verifySources(source_dir):
    """
    :param source_dir: str | unicode
    :return:
    """
    missing = [f for f in REQUIRED_FILES if not isfile(join(source_dir, f))]
    if missing:
        die('Missing project file(s) in {}: {}'.format(source_dir, ', '.join(missing)))


# ---------------------------------------------------------------------------
# Backend: PyInstaller
# ---------------------------------------------------------------------------
def buildPyinstaller(args, upx_dir):
    pipInstall(['pyinstaller'], args.skip_install)
    cmd = [
        executable, '-m', 'PyInstaller',
        '--onefile',
        '--noconfirm',
        '--clean',
        '--name', args.name,
        '--distpath', args.dist_dir,
        '--workpath', join(args.dist_dir, '_build'),
        '--specpath', join(args.dist_dir, '_build')]
    if args.no_console:
        cmd.append('--windowed')
    else:
        cmd.append('--console')  # explicit: keep stdin/stdout so getpass() & print() work
    if not args.no_upx and upx_dir:
        cmd += ['--upx-dir', upx_dir]
    elif not args.no_upx:
        print('NOTE: UPX not found on PATH -- building without it. '
              'Install UPX and re-run for a smaller exe, or pass --no-upx '
              'to silence this note.')
    for m in PYINSTALLER_EXCLUDES:
        cmd += ['--exclude-module', m]
    if args.icon:
        cmd += ['--icon', args.icon]
    # Pull the sibling modules in explicitly so PyInstaller's static
    # analysis is guaranteed to find them even if the try/except import
    # fallback in miniblocker.py confuses its import scanner.
    for extra in ('rdpdisconnect', 'hostutils', 'netgeo'):
        cmd += ['--hidden-import', extra]
    cmd.append(args.entry)
    print('\n$ {}'.format(' '.join(cmd)))
    run(cmd, check=True, cwd=args.source_dir)
    return join(args.dist_dir, args.name + '.exe')


# ---------------------------------------------------------------------------
# Backend: Nuitka
# ---------------------------------------------------------------------------
def buildNuitka(args, upx_dir):
    pipInstall(['nuitka', 'ordered-set', 'zstandard'], args.skip_install)
    out_name = args.name + '.exe'
    cmd = [executable, '-m', 'nuitka', '--onefile', '--lto=yes', '--assume-yes-for-downloads', '--remove-output',
           '--output-dir=' + args.dist_dir, '--output-filename=' + out_name]
    if args.no_console:
        cmd.append('--windows-console-mode=disable')
    # else: leave Nuitka's default (a real, visible console) so the program
    # can print and read the password prompt.
    if not args.no_upx:
        if upx_dir:
            cmd.append('--onefile-tempdir-spec={TEMP}/mrb_%PID%')
        # Nuitka's onefile mode already compresses its payload; UPX on top
        # of the bootstrap stub itself is applied automatically when `upx`
        # is discoverable on PATH, no extra flag required.
    if args.icon:
        cmd.append('--windows-icon-from-ico=' + args.icon)
    cmd.append(args.entry)
    print('\n$ {}'.format(' '.join(cmd)))
    run(cmd, check=True, cwd=args.source_dir)
    built = join(args.dist_dir, out_name)
    if not isfile(built):
        # Older Nuitka versions place it next to the entry script instead.
        alt = join(args.source_dir, out_name)
        if isfile(alt):
            makedirs(args.dist_dir, exist_ok=True)
            move(alt, built)
    return built


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parseArgs(argv):
    p = ArgumentParser(description=__doc__, formatter_class=RawDescriptionHelpFormatter)
    p.add_argument('--tool', choices=['pyinstaller', 'nuitka'],
                   help="Build backend. If omitted, you'll be asked interactively.")
    p.add_argument('--entry', default='miniblocker.py', help='Entry script.')
    p.add_argument('--name', default='MiniRDPBlocker', help='Output exe base name.')
    p.add_argument('--source-dir', default=dirname(abspath(__file__)),
                   help="Folder containing the project's .py files.")
    p.add_argument('--dist-dir', default=join(getcwd(), 'dist'),
                   help='Output folder for the built exe.')
    p.add_argument('--icon', default=None, help='Optional .ico file.')
    # This is a CLI tool: it MUST be a console app so it can print output and
    # read the password via getpass()/input(). Console is therefore the
    # default. --no-console (alias --windowed) opts into a silent GUI binary
    # that can neither print nor prompt.
    console = p.add_mutually_exclusive_group()
    console.add_argument('--console', dest='no_console', action='store_false',
                         help='Build a console app so output and the password prompt work (DEFAULT).')
    console.add_argument('--no-console', '--windowed', dest='no_console', action='store_true',
                         help='Build a GUI/no-console app (cannot print or prompt for a password).')
    p.set_defaults(no_console=False)
    p.add_argument('--no-upx', action='store_true', help='Disable UPX compression.')
    p.add_argument('--skip-install', action='store_true',
                   help="Don't auto pip-install the build backend.")
    p.add_argument('-y', '--yes', action='store_true',
                   help="Don't ask for confirmation before building.")
    return p.parse_args(argv)


def askTool():
    """
    :return:
    """
    print('Which backend do you want to build with?')
    print('  1) PyInstaller  -- simpler, very widely used, good UPX support')
    print('  2) Nuitka       -- compiles to C first, usually faster & smaller output')
    while True:
        choice = input('Enter 1 or 2: ').strip()
        if choice == '1':
            return 'pyinstaller'
        if choice == '2':
            return 'nuitka'
        print('Please enter 1 or 2.')


def main(argv=None):
    args = parseArgs(argv)
    checkWindows()
    args.source_dir = abspath(args.source_dir)
    args.dist_dir = abspath(args.dist_dir)
    verifySources(args.source_dir)
    tool = args.tool or askTool()
    upx_dir = None if args.no_upx else findUpx()
    print('\nBuild plan:')
    print('  tool         : {}'.format(tool))
    print('  entry        : {}'.format(join(args.source_dir, args.entry)))
    print('  output name  : {}.exe'.format(args.name))
    print('  dist dir     : {}'.format(args.dist_dir))
    print('  console app  : {}'.format('no (GUI/silent)' if args.no_console else 'yes (prints + password prompt work)'))
    print('  UPX          : {}'.format(upx_dir or ('disabled' if args.no_upx else 'not found')))
    print('  python       : {} ({})'.format(executable, get_platform()))
    if not args.yes:
        reply = input('\nProceed with build? [y/N] ').strip().lower()
        if reply not in ('y', 'yes'):
            print('Aborted.')
            return 0
    makedirs(args.dist_dir, exist_ok=True)
    if tool == 'pyinstaller':
        exe_path = buildPyinstaller(args, upx_dir)
    else:
        exe_path = buildNuitka(args, upx_dir)
    if isfile(exe_path):
        size_mb = getsize(exe_path) / (1024 * 1024)
        print('\nBuild finished: {}  ({:.1f} MB)'.format(exe_path, size_mb))
        return 0
    die("Build appears to have completed but the expected exe was not found at {}. Check the tool's output.".format(
        exe_path))
    return None


if __name__ == '__main__':
    exit(main())
