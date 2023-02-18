from __future__ import annotations

import asyncio
import asyncio.subprocess
from concurrent.futures import ThreadPoolExecutor
import datetime
from enum import Enum
import logging
import os
from pathlib import Path
import re
import socket
import ssl
import time
from typing import Optional

import aiohttp_socks.utils
from stem import Signal as _Signal
from stem import SocketClosed
from stem.control import Controller as _Controller

from . import utils
from .utils import PublicIPService


__all__ = ["SocksProxy", "Tor", "TorRC"]


def __getattr__(name):
    if name not in __all__:
        raise AttributeError(name)


log = logging.getLogger(__name__)
DEBUG = False
DEFAULT_PORT = 10080
INSTANCES = []

if DEBUG:
    log.setLevel(10)


def _check_requirements(tor: Tor = None):
    exc = None
    try:
        bin_path = utils.TOR_BIN_EXECUTABLE
        if tor:
            bin_path = tor.binary_path
        if not bin_path.exists():
            utils.APP_DATA.mkdir(parents=True, exist_ok=True)
            utils.TOR_BIN_FOLDER.mkdir(parents=True, exist_ok=True)
            utils.TOR_DATA_FOLDER.mkdir(parents=True, exist_ok=True)
            utils.download(utils.TOR_BIN_FOLDER, version=0)
        if tor:
            if bin_path.exists():
                tor.binary_path = bin_path
    except Exception as e:
        exc = e
    finally:
        if not exc:
            return True
        return False


class ProxyType(Enum):
    SOCKS4 = 1
    SOCKS5 = 2
    HTTP = 3


class SocksProxy:
    def __init__(
        self,
        host,
        port,
        type=ProxyType.SOCKS5,
    ):
        if port == 0:
            raise ValueError("no port specified!")

        self.scheme = "socks5"
        self._start_ts = datetime.datetime.now()
        self._newnym_ts = self._start_ts
        if type is ProxyType.SOCKS4:
            self.scheme = "socks4"

        self.host = host
        self.port = port

        self.loop: asyncio.BaseEventLoop = None
        self._public_ip = ""
        self._public_ip_provided_by = None
        self._latency = 0

    @property
    def latency(self):
        return self._latency

    @property
    def socks_url(self) -> str:
        return "%s://%s:%d" % (self.scheme, self.host, self.port)

    @property
    def host_port_tuple(self):
        return tuple(self)

    @property
    def public_ip(self):
        return self._public_ip

    @public_ip.setter
    def public_ip(self, val):
        if val != self._public_ip:
            self._newnym_ts = datetime.datetime.now()
        self._public_ip = val

    async def open_connection(
        self,
        host,
        port,
        ssl_context: ssl.SSLContext = None,
        server_hostname: str = None,
        limit: int = 2**16,
    ):
        if port in (443, 8443) or ssl_context:
            if not ssl_context:
                ssl_context = ssl.create_default_context()
            if not server_hostname:
                # server_hostname should be passed when using ssl
                # instead of directly throwing an exception
                # first try to 'fix' this
                if not re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                    # host does not look like an ip address
                    # set it as the server_hostname
                    server_hostname = host

        cstart = time.perf_counter()
        r, w = await aiohttp_socks.utils.open_connection(
            proxy_url=self.socks_url,
            host=host,
            port=port,
            proxy_port=self.port,
            proxy_host=self.host,
            proxy_type=aiohttp_socks.ProxyType.SOCKS5,
            ssl=ssl_context,
            server_hostname=server_hostname,
            limit=limit,
        )
        cstop = time.perf_counter()
        self._latency = cstop - cstart
        return r, w

    async def _open_connection(
        self,
        host: str,
        port: int,
        *,
        ssl_context: ssl.SSLContext = None,
        server_hostname: str = None,
        limit=2**16,
        **kw,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        import struct

        cstart = time.perf_counter()
        # connect to the proxy
        preader, pwriter = await asyncio.open_connection(self.host, self.port, **kw)

        # we do not authenticate to our local proxies
        pwriter.write(bytearray([0x05, 0x01, 0x00]))

        # so we don't need to read the response either
        _ = await preader.read(2)
        # print( _ )

        host_packed = b""
        typ = 0x03  # assuming a hostname default

        if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            # its an ip address
            host_packed = socket.inet_aton(host)
            # but it could also be an ip
            typ = 0x01

        elif re.search(r"([^0-9]{2,3})+", host):
            # server_hostname = host
            # as we already filtered ip addresses. this is probably a dns name
            host_packed = struct.pack(f"!B{len( host )}s", len(host), host.encode())
            # or just the hostname
            typ = 0x03

        else:
            # probaby ip6
            typ = 0x04
            # not implemented yet
        # print('host packed : ', host_packed)
        port_packed = struct.pack("!H", port)
        pwriter.write(bytearray([0x05, 0x01, 0x00, typ, *host_packed, *port_packed]))

        _ = await preader.read(6)
        loop = asyncio.get_running_loop()

        # here the real shit happens
        if ssl_context is not None or port == 443:
            # if not server_hostname:
            #     if host:
            #         best luck
            # server_hostname = host
            # else:
            #     raise Exception( "you need server_hostname when you use ssl/ttls" )
            await _upgrade_stream_tls(
                preader,
                pwriter,
                ssl_context,
                server_side=False,
                server_hostname=server_hostname,
            )
        self._latency = time.perf_counter() - cstart
        return preader, pwriter

    def __iter__(self):
        return iter([self.host, self.port])

    def __str__(self):
        return self.socks_url

    def __repr__(self):
        return (
            "%s(host = %s, port = %d, scheme = %s)[latency: %.2fs, ip: %s, ip age: %s]"
            % (
                self.__class__.__name__,
                self.host,
                self.port,
                self.scheme,
                self.latency,
                self.public_ip,
                datetime.datetime.now() - self._newnym_ts,
            )
        )


class Tor(object):
    _EXECUTOR = ThreadPoolExecutor()

    def __init__(self, num_socks=15, start_port=DEFAULT_PORT):
        """
        Creates a Tor proxy process
        :param dict settings: torrc settings (optional)
            key_name,value will be translated to a line of: KeyName str(value)
        """

        self.config = None
        self.binary_path = utils.TOR_BIN_EXECUTABLE
        self.status_bootstrap = 0

        self._exception = None
        self._running = False
        self._process = None
        self._proxies = []
        self._controller = None
        self._tasks = set()
        self._num_socks = num_socks
        self._start_port = utils.free_port(start_port)

    @property
    def process(self) -> asyncio.subprocess.Process:
        return self._process

    @property
    def running(self) -> bool:
        if self.process and self.process.returncode is None:
            return True
        return False

    async def start(self, torrc: TorRC = None):
        await asyncio.get_running_loop().run_in_executor(
            self._EXECUTOR, _check_requirements, self
        )

        if not torrc:
            if self.config:
                torrc = self.config

        if not torrc:
            i = 0
            data_directory = utils.TOR_DATA_FOLDER
            while _data_dir_locked(data_directory):
                new_data_directory = data_directory.with_name(str(i))
                log.warning(
                    f"{data_directory} is locked. trying another ({new_data_directory})"
                )
                i += 1
                data_directory = new_data_directory

            if not data_directory.exists():
                data_directory.mkdir(parents=True, exist_ok=True)

            running_instances = [t for t in INSTANCES]
            if len(running_instances) > 0:
                # found more instances
                last_instance = running_instances[-1]
                highest_in_use = max(last_instance.config.socks_port)
                # have 100 port gap betweem instances
                port = utils.free_port(highest_in_use) + 100

            else:
                port = utils.free_port(DEFAULT_PORT)

            torrc = TorRC(
                socks_ports=[port + n for n in range(0, self._num_socks)],
                data_directory=data_directory,
            )

        torrc.set_notify_on_change(self._on_config_change)
        self.config = torrc
        if self not in INSTANCES:
            INSTANCES.append(self)
        coro = asyncio.subprocess.create_subprocess_exec(
            self.binary_path,
            "__OwningControllerProcess",
            str(os.getpid()),
            *torrc.as_cmdline(),
            # "-f" ,
            # "-" ,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._process = await coro
        retry = 3
        while True:
            line = None
            try:
                line = await asyncio.wait_for(self.process.stdout.readline(), 1)
                log.debug(line)
            except asyncio.TimeoutError:
                pass
            if not line:
                # print( retry )
                if not retry:
                    break
                if self.status_bootstrap > 0:
                    continue
                retry -= 1
                continue
            try:
                self.status_bootstrap = int(
                    re.search(rb"Bootstrapped ([0-9]+)%", line)[1]
                )
                log.info("bootstrapped %s" % self.status_bootstrap)
                if self.status_bootstrap == 100:
                    break
            except TypeError:
                pass

        if self._num_socks > 1:
            current_ports = self.config.socks_port

            try:
                # for _ in range( self._num_socks ):
                #     last_port = current_ports[ -1 ]
                #     while last_port in [self.config.control_port, self.config.dns_port, self.config.http_tunnel_port,
                #                         *self.config.socks_port]:
                #         last_port += 2
                #     current_ports.append( last_port )

                self.config.socks_port = current_ports
            except:
                import traceback

                traceback.print_exc()

        # self._num_socks = -1
        return self

    @property
    def controller(self) -> _Controller:
        if not self._controller:
            if not self.process:
                return
            if not self.status_bootstrap == 100:
                return
            self._controller = _Controller.from_port(port=self.config.control_port)
            self._controller.authenticate()
        elif not self._controller.is_alive():
            self._controller = None
            return self.controller
        return self._controller

    def _on_config_change(self, key, val):
        if not self.controller:
            return asyncio.get_running_loop().call_later(
                1, self._on_config_change, key, val
            )

        key = "".join(k.capitalize() for k in key.split("_"))

        if isinstance(val, int):
            val = [str(val)]
        if isinstance(val, list):
            val = [str(v) for v in val]
        try:
            self.controller.set_conf(key, val)
        except SocketClosed:
            self._controller = None
            self._on_config_change(key, val)

    @property
    def proxies(self):
        def on_done_latency(task: asyncio.Task):
            name = task.get_name()
            try:
                self._tasks.discard(task)
                proxy = task.result()
                if not proxy:
                    exc = task.exception()
                    raise exc
            except Exception as e:
                try:
                    proxy = [_ for _ in self._proxies if str(_.port) == str(name)][0]
                    task = asyncio.ensure_future(
                        PublicIPService.get_ip(proxy, timeout=5)
                    )
                    # print('RE ADDING TASK %s FOR PROXY %s' % (task, proxy))
                    task.set_name(proxy.port)
                    task.add_done_callback(on_done_latency)

                    self._tasks.add(task)
                    return
                except IndexError:
                    pass
                except:
                    log.debug(
                        "on done latency - inner exception -  exception re-adding task",
                        exc_info=True,
                    )

        # store the proxies in a local variable
        # so we can reuse them (and save on latency calcs)
        prxs = []
        for p in self._proxies:
            prxs.append(p)
        self._proxies.clear()
        host = "127.0.0.1"

        if self.config:
            for port in self.config.socks_port:
                candidate = [p for p in prxs if p.port == port]
                if candidate:
                    proxy = candidate[0]
                elif isinstance(port, (str)):
                    if ":" in port:
                        host, port = port.split(":")
                    proxy = SocksProxy(host=host, port=int(port))
                else:
                    proxy = SocksProxy(host="127.0.0.1", port=int(port))

                if not proxy.latency or not proxy.public_ip:
                    if not any([t.get_name() == str(proxy.port) for t in self._tasks]):
                        # if not proxy.port in self._tasks:
                        # only update latency/ip when not already scheduled
                        task = asyncio.ensure_future(
                            PublicIPService.get_ip(proxy, timeout=5)
                        )
                        task.set_name(proxy.port)
                        task.add_done_callback(on_done_latency)
                        self._tasks.add(task)
                self._proxies.append(proxy)
        return self._proxies

    def newnym(self):
        if self.controller.get_newnym_wait() > 0:
            return False
        self.controller.signal(_Signal.NEWNYM)
        self._proxies.clear()
        self.proxies
        return True

    def _clear_latency(self):
        for _ in self.proxies:
            _._latency = None

    def stop(self):
        self.process.kill()
        self.config = None
        INSTANCES.remove(self)

    def __repr__(self):
        nports = ""
        if self.config and self.config.control_port:
            nports = f"socksports: {len( self.config.socks_port )}"
        return f"<{self.__class__.__name__} < running {self.running}, {nports} >"


def _data_dir_locked(datadir: Path):
    try:
        b = datadir / "control_auth_cookie"
        if b.exists():
            return True
        else:
            #        if not b:
            #            shutil.rmtree(datadir)
            return False
    except PermissionError:
        return True
    except FileNotFoundError:
        return False
    except BaseException as e:
        raise e
    return False


class TorRC(dict):
    def __init__(
        self,
        socks_ports: list[int] = None,
        control_port=0,
        dns_port=0,
        http_tunnel_port=0,
        data_directory="data",
        new_circuit_period=15,
        cookie_authentication=1,
        enforce_distinct_subnets=0,
        hashed_control_password="qwerty",
    ):
        self._notify_on_change = None

        first_port = DEFAULT_PORT
        # if not isinstance( socks_ports , (list ,) ):
        #     socks_ports = [ socks_ports ]

        if socks_ports and len(socks_ports) > 0 and socks_ports[0] is not None:
            first_port = utils.free_port(socks_ports[-1])
        else:
            socks_ports = [first_port]

        self.socks_port = socks_ports
        self.control_port = control_port or first_port + 1
        self.dns_port = dns_port or first_port + 2
        self.http_tunnel_port = http_tunnel_port or first_port + 3

        self.data_directory = data_directory
        self.new_circuit_period = new_circuit_period
        self.cookie_authentication = cookie_authentication
        self.enforce_distinct_subnets = enforce_distinct_subnets
        # self.hashed_control_password = [
        #      hashed_control_password for n in range( len( self.socks_port ) )]
        #

        super().__init__(self.__dict__)
        super().__setattr__("__dict__", self)

    def set_notify_on_change(self, callback):
        self._notify_on_change = callback

    def __setattr__(self, key, value):
        super().__setattr__(key, value)
        if key == "_notify_on_change":
            return
        if self._notify_on_change:
            self._notify_on_change(key, value)

    def as_cmdline(self):
        cmdline = []
        for key, value in self.items():
            if key[0] == "_":
                continue
            key = "".join(k.capitalize() for k in key.split("_"))
            if isinstance(value, (str, int)):
                cmdline.extend([f"--{key}", f"{value}"])
            elif isinstance(
                value,
                (
                    list,
                    tuple,
                ),
            ):
                for val in value:
                    cmdline.extend([f"--{key}", f"{val}"])
            else:
                cmdline.extend([f"--{key}", f"{str( value )}"])
        return cmdline

    def as_string(self):
        """

        :return:
        """
        config_str = ""
        for key, value in self.items():
            if key[0] == "_":
                continue
            key = "".join(k.capitalize() for k in key.split("_"))
            if isinstance(value, (str, int)):
                config_str += f"{key} {value}\n"
            elif isinstance(
                value,
                (
                    list,
                    tuple,
                ),
            ):
                for val in value:
                    config_str += f"{key} {val}\n"
            else:
                config_str += f"{key} {str( value )}\n"
        return config_str

    def as_bytes(self):
        return self.as_string().encode("utf-8")


async def _upgrade_stream_tls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_side: bool = False,
    server_hostname: str = None,
    loop: asyncio.BaseEventLoop = None,
):
    """ """
    import sys

    if 3 >= sys.version_info.major and sys.version_info.minor >= 10:
        # set the correct protocol in case user provided wrong protocol
        # which may happen a lot since the ssl implementation likes throwing meaningless errors.
        if server_side:
            proto = ssl.PROTOCOL_TLS_SERVER
        else:
            proto = ssl.PROTOCOL_TLS_CLIENT
    else:
        proto = ssl.PROTOCOL_TLS

    if not ssl_context:
        if not server_side:
            # ssl_context = ssl.create_default_context()
            import certifi

            ssl_context = ssl.SSLContext(protocol=proto)
            ssl_context.load_verify_locations(certifi.where())
            # ssl_context = ssl.create_default_context( ssl.Purpose.SERVER_AUTH )

    kwargs = dict(
        sslcontext=ssl_context,
        server_side=server_side,
    )
    if server_hostname:
        kwargs.update(dict(server_hostname=server_hostname))

    transport = writer.transport
    protocol = transport.get_protocol()
    loop = loop or asyncio.get_event_loop()
    new_transport = await loop.start_tls(
        transport=transport, protocol=protocol, **kwargs
    )

    setattr(reader, "_transport", new_transport)
    setattr(writer, "_transport", new_transport)
    # reader._transport = new_transport
    # writer._transport = new_transport
