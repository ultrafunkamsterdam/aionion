import io
import json
import logging
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import tarfile
from typing import AnyStr
from typing import Awaitable
from typing import Callable
from typing import IO
from typing import Union
import urllib.parse

import async_timeout
import bs4


try:
    # python >= 3.9
    from packaging.version import Version
except ImportError:
    # python < 3.9
    from distutils.version import LooseVersion as Version

WIN = sys.platform.startswith("win")
MAC = sys.platform.startswith("darwin")
UNIX = sys.platform.startswith(("linux", "linux2"))

log = logging.getLogger(__name__)


def get_appdata_dir(append="") -> Path:
    """
    Returns a parent directory path
    where persistent application data can be stored.

    # linux: ~/.local/share
    # macOS: ~/Library/Application Support
    # windows: C:/Users/<USER>/AppData/Roaming
    """
    home = Path.home()
    if WIN:
        return home / "AppData/Roaming" / append
    elif UNIX:
        return home / ".local/share" / append
    elif MAC:
        return home / "Library/Application Support" / append


def get_path(path: Union[AnyStr, Path] = None) -> Path:
    """
    returns the absolute path or,
    in case of pyinstaller, the relative-to-package path

    :param path:
    :return:
    """
    if not path:
        path = ""
    if isinstance(path, bytes):
        path = path.decode()
    if isinstance(path, Path):
        path = str(path)
    return Path(
        os.path.join(
            getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__))), path
        )
    )


PKG_DIR = get_path(__file__).parent
APP_DATA = get_appdata_dir() / __package__

TOR_BIN_FOLDER = APP_DATA / "bin"
TOR_DATA_FOLDER = APP_DATA / "data"
TOR_BIN_EXECUTABLE = TOR_BIN_FOLDER / "tor" / ("tor.exe" if WIN else "tor")

TOR_VERSION_REGEX = re.compile(r"[+-]?([0-9]*[.])?[0-9]+")
URL_BASE = "https://dist.torproject.org/torbrowser/"
URL_PLAT_NAME = WIN and "windows" or MAC and "osx" or UNIX and "linux"

# fix for linux not finding libcrypto
if UNIX | MAC:
    os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(
        [os.environ.get("LD_LIBRARY_PATH", ""), str(TOR_BIN_FOLDER / "tor")]
    )


def configure_console():
    posix = False
    try:
        from ctypes import windll
    except ImportError:
        posix = True
    if posix:
        return
    # must be windows
    from platform import win32_ver

    if Version(win32_ver()[1]) >= Version("10.0.10586"):
        # noinspection PyUnboundLocalVariable
        windll.kernel32.SetConsoleMode(windll.kernel32.GetStdHandle(-11), 7)
        logging.getLogger(__package__).debug("windows console set to modern mode")


def download(
    output_dir: Union[str, Path] = TOR_BIN_FOLDER, version: Union[int, float] = 0
):
    version = str(version)
    output_dir = Path(output_dir)

    try:
        from urllib.request import urlopen
    except ImportError:
        # noinspection PyUnresolvedReferences
        from urllib2 import urlopen

    output_dir.mkdir(755, True, True)

    # we don't like ssl error in this case
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with urlopen(URL_BASE, context=ctx) as response:
        soup = bs4.BeautifulSoup(response, "lxml")
        links = soup.find_all("a", href=TOR_VERSION_REGEX)
        high_to_low = sort_href_version_ref(links)
        highest = high_to_low[0]
        next_url = urllib.parse.urljoin(URL_BASE, highest[1])  # 1 is index of value
        log.info("moving to next url : %s " % next_url)

    with urlopen(next_url, context=ctx) as response:
        soup = bs4.BeautifulSoup(response, "lxml")
        arch = "64"
        plat = URL_PLAT_NAME
        download_type = "expert-bundle"
        ext = "tar.gz"
        elems = soup.find_all(
            "a",
            href=lambda x: all([w in x for w in (plat, arch, download_type)])
            and x.endswith(ext),
        )
        log.debug("found links:")
        for elem in elems:
            log.debug(elem.attrs.get("href"))
        elem = elems[0]  # assuming first is best
        log.debug("picked %s as the best candidate" % elem.attrs.get("href"))
        next_url = urllib.parse.urljoin(next_url, elem.attrs.get("href"))
        with urlopen(next_url) as response:
            fileobj = io.BytesIO(response.read())
            unpack_tar(fileobj, output_dir)


def unpack_tar(buffer: IO, output_dir: Union[str, Path]):
    tf = tarfile.open(fileobj=buffer)
    for name in tf.getnames():
        log.info("completed: %s" % name)
    tf.extractall(output_dir)


def sort_href_version_ref(elements):
    versions = {
        float(TOR_VERSION_REGEX.search(a.attrs.get("href"))[0]): a.attrs.get("href")
        for a in elements
    }
    return [x for x in sorted(versions.items(), key=lambda i: i[0], reverse=True)]


def run_in_background_thread(tor):
    import threading
    import asyncio

    class BackgroundThread(threading.Thread):
        def __init__(self, tor: "Tor"):
            super().__init__(target=self.start_loop)
            self.loop = asyncio.new_event_loop()
            self.tor = tor

        def start_loop(self):
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.tor.start())
            self.loop.run_until_complete(self.keep_running())

        async def keep_running(self):
            while True:
                if not self.tor.running:
                    print("tor has quit. restarting it now...")
                    await self.tor.start()
                await asyncio.sleep(5)

    bgt = BackgroundThread(tor)
    bgt.daemon = True
    bgt.start()
    return bgt


def free_port(hint: int = 0) -> int:
    """
    returns a free port available to bind
    :param hint: int (optional) => pick this port. if not available return higher free port.
     defaults to automatic
    """
    free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        free_socket.bind(("127.0.0.1", hint))
    except OSError as e:
        if hint != 0:
            return free_port(hint + 1)
    free_socket.listen(5)
    port: int = free_socket.getsockname()[1]
    free_socket.close()
    return port


class PublicIPService:
    APIS = [
        # tuples containing
        #  host
        #  port
        #  uri
        #  key name of json response
        ("httpbin.org", 443, "/ip", "origin"),
        ("api.ipify.org", 443, "/?format=json", "ip"),
        ("ip.seeip.org", 443, "/json", "ip"),
    ]

    @classmethod
    async def get_ip(cls, proxy, timeout=2):
        return await cls(proxy, timeout).lookup()

    def __init__(self, proxy, timeout=2):
        self.timeout = timeout
        self.proxy = proxy
        self.log = logging.getLogger(self.__class__.__name__)

    async def lookup(self, open_connection: Callable[[str, int], Awaitable] = None):
        """
        :param open_connection: optional: the open_connection function to use
                                default: use the one from self.proxy
        """
        if not open_connection:
            open_connection = self.proxy.open_connection
        success = None
        result = None
        napis = len(self.APIS)
        reader = None
        writer = None
        for idx, (host, port, path, key) in enumerate(self.APIS):
            try:
                async with async_timeout.timeout(self.timeout):
                    reader, writer = await open_connection(host, port)
                    writer.write(
                        f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n\r\n".encode()
                    )
                    headers = await reader.readuntil(b"\r\n\r\n")
                    # self.log.debug( 'headers: %s' % headers.decode() )
                    body = await reader.read()
                    body_str = body.decode()
                    # self.log.debug( 'body: %s' % body_str )
                    json_response = json.loads(body_str)
                    result = json_response[key]
                    self.proxy.public_ip = result
                    self.proxy._public_ip_provided_by = host
                    success = True
                    self.log.debug(f"found ip {result} from {host} for proxy: {self}")
                    break
            except (
                asyncio.TimeoutError,
                json.JSONDecodeError,
                UnicodeDecodeError,
                KeyError,
            ) as e:
                if idx >= napis - 1:
                    self.log.debug(
                        f"exception: {e} when trying to get public ip from {host}:{port} - index {idx}"
                    )
                    raise LookupError(
                        "could not retrieve the ip address for {proxy} from any of the public apis".format(
                            proxy=self.proxy
                        )
                    )
                continue
            finally:
                if writer:
                    if not writer.is_closing():
                        log.debug(f"closing writer to {host}:{port}")
                        writer.close()
                        await writer.wait_closed()
        return self.proxy


import asyncio
from itertools import islice



def limited_as_completed(coros, limit):
    """
    Run the coroutines (or futures) supplied in the
    iterable coros, ensuring that there are at most
    limit coroutines running at any time.
    Return an iterator whose values, when waited for,
    are Future instances containing the results of
    the coroutines.
    Results may be provided in any order, as they
    become available.
    """
    futures = [asyncio.ensure_future(c) for c in islice(coros, 0, limit)]

    async def first_to_finish():
        while True:
            await asyncio.sleep(0)
            for f in futures:
                if f.done():
                    futures.remove(f)
                    try:
                        newf = next(coros)
                        futures.append(asyncio.ensure_future(newf))
                    except StopIteration as e:
                        pass
                    return f.result()

    while len(futures) > 0:
        yield first_to_finish()
