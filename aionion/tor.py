from __future__ import annotations

import asyncio
import asyncio.subprocess
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
import logging
import os
import re
import socket
import ssl
import time
from typing import Optional

from stem import Signal as _Signal
from stem import SocketClosed
from stem.control import Controller as _Controller

from aionion import support
from .support import PublicIPService


log = logging.getLogger( __name__ )

DEFAULT_PORT = 10080
DEFAULT_LIMIT = 2 ** 16

INSTANCE = []


def _check_requirements(tor: Tor = None):
    
    bin_path = support.TOR_BIN_EXECUTABLE
    if tor:
        bin_path = tor.binary_path
    if not bin_path.exists():
        support.APP_DATA.mkdir( parents = True , exist_ok = True )
        support.TOR_BIN_FOLDER.mkdir( parents = True , exist_ok = True )
        support.TOR_DATA_FOLDER.mkdir( parents = True , exist_ok = True )
        support.download( support.TOR_BIN_FOLDER , version = 0 )
        return True




class ProxyType( Enum ):
    SOCKS4 = 1
    SOCKS5 = 2
    HTTP = 3


class SocksProxy:
    
    def __init__(
            self ,
            host ,
            port ,
            type = ProxyType.SOCKS5 ,
            ):
        if port == 0:
            raise ValueError( "no port specified!" )
        
        self.scheme = "socks5"
        
        if type is ProxyType.SOCKS4:
            self.scheme = "socks4"
        
        self.host = host
        self.port = port
        
        self.loop: asyncio.BaseEventLoop = None
        self._public_ip = ""
        self._public_ip_provided_by = None
        self._latency = 0
    
    
    @property
    def latency( self ):
        return self._latency
    
    
    @property
    def socks_url( self ) -> str:
        return "%s://%s:%d" % (self.scheme , self.host , self.port)
    
    
    @property
    def host_port_tuple( self ):
        return tuple( self )
    
    
    @property
    def public_ip( self ):
        return self._public_ip
    
    
    async def open_connection(
            self ,
            host: str ,
            port: int ,
            * ,
            ssl_context: ssl.SSLContext = None ,
            server_hostname: str = None ,
            limit = 2 ** 16 ,
            **kw ,
            ) -> tuple[ asyncio.StreamReader , asyncio.StreamWriter ]:
        
        import struct
        
        cstart = time.perf_counter()
        # connect to the proxy
        preader , pwriter = await asyncio.open_connection( self.host , self.port , **kw )
        
        # we do not authenticate to our local proxies
        pwriter.write( bytearray( [ 0x05 , 0x01 , 0x00 ] ) )
        
        # so we don't need to read the response either
        _ = await preader.read( 2 )
        # print( _ )
        
        host_packed = b""
        typ = 0x03  # assuming a hostname default
        
        if re.search( r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" , host ):
            # its an ip address
            host_packed = socket.inet_aton( host )
            # but it could also be an ip
            typ = 0x01
        
        elif re.search( r"([^0-9]{2,3})+" , host ):
            # server_hostname = host
            # as we already filtered ip addresses. this is probably a dns name
            host_packed = struct.pack( f"!B{len( host )}s" , len( host ) , host.encode() )
            # or just the hostname
            typ = 0x03
        
        else:
            # probaby ip6
            typ = 0x04
            # not implemented yet
        # print('host packed : ', host_packed)
        port_packed = struct.pack( "!H" , port )
        pwriter.write(
            bytearray( [ 0x05 , 0x01 , 0x00 , typ , *host_packed , *port_packed ] )
            )
        
        _ = await preader.read( 6 )
        loop = asyncio.get_running_loop()
        
        # here the real shit happens
        if ssl_context is not None or port == 443:
            # if not server_hostname:
            #     if host:
            #         best luck
            # server_hostname = host
            # else:
            #     raise Exception( "you need server_hostname when you use ssl/ttls" )
            await upgrade_stream_tls(
                preader , pwriter , ssl_context , server_side = False, server_hostname = server_hostname
                )
        self._latency = time.perf_counter() - cstart
        return preader , pwriter
    
    
    def __iter__( self ):
        return iter( [ self.host , self.port ] )
    
    
    def __str__( self ):
        return self.socks_url
    
    
    def __repr__( self ):
        return "%s(host = %s, port = %d, scheme = %s)[latency: %.2fs, ip: %s]" % (
            self.__class__.__name__ ,
            self.host ,
            self.port ,
            self.scheme ,
            self.latency ,
            self.public_ip
            )



class Tor( object ):
    
    _EXECUTOR = ThreadPoolExecutor()

    def __init__( self , num_socks = 15 ):
        """
        Creates a Tor proxy process
        :param dict settings: torrc settings (optional)
            key_name,value will be translated to a line of: KeyName str(value)
        """
        self.config = None
        self.binary_path = support.TOR_BIN_EXECUTABLE
        self.status_bootstrap = 0
        self.debug = False
        self._exception = None
        self._running = False
        self._process = None
        self._proxies = [ ]
        self._controller = None
        self._tasks = set()
        self._num_socks = num_socks
        if self not in INSTANCE:
            INSTANCE.append(self)
    
    @property
    def process( self ) -> asyncio.subprocess.Process:
        return self._process
    
    
    @property
    def running( self ) -> bool:
        if self.process and self.process.returncode is None:
            return True
        return False
    
    
    async def start( self , torrc: TorRC = None ):
        
        await asyncio.get_running_loop().run_in_executor(self._EXECUTOR, _check_requirements, self)

        if not torrc:
            if self.config:
                torrc = self.config
                
        if not torrc:
            if len(INSTANCE) == 1:
                data_directory = support.TOR_DATA_FOLDER
            else:
                data_directory = support.TOR_DATA_FOLDER / str(len(INSTANCE))
            
            if not data_directory.exists():
                data_directory.mkdir( parents = True , exist_ok = True )
            torrc = TorRC( data_directory = data_directory )
        
       
        torrc.set_notify_on_change( self._on_config_change )
        self.config = torrc
        
        coro = asyncio.subprocess.create_subprocess_exec(
            self.binary_path ,
            "__OwningControllerProcess" ,
            str( os.getpid() ) ,
            *torrc.as_cmdline() ,
            # "-f" ,
            # "-" ,
            stdin = asyncio.subprocess.PIPE ,
            stdout = asyncio.subprocess.PIPE ,
            stderr = asyncio.subprocess.STDOUT ,
            )
        
        self._process = await coro
        retry = 3
        while True:
            line = None
            try:
                line = await asyncio.wait_for( self.process.stdout.readline() , 1 )
                log.debug( line )
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
                    re.search( rb"Bootstrapped ([0-9]+)%" , line )[ 1 ]
                    )
                log.info( "bootstrapped %s" % self.status_bootstrap )
                if self.status_bootstrap == 100:
                    break
            except TypeError:
                pass
        
        if self._num_socks > 1:
            current_ports = self.config.socks_port
            
            try:
                for _ in range( self._num_socks ):
                    last_port = current_ports[ -1 ]
                    while last_port in [self.config.control_port, self.config.dns_port, self.config.http_tunnel_port,
                                        *self.config.socks_port]:
                        last_port += 2
                    current_ports.append( last_port )
                
                self.config.socks_port = current_ports
                
                # self.controller.set_conf( 'socksport', [str(p) for p in ports_in_use])
                # self.config.socks_port.extend(list(range(1)))
            except:
                import traceback
                
                traceback.print_exc()
        self._num_socks = -1
        return self
    
    
    @property
    def controller( self ) -> _Controller:
        if not self._controller:
            if not self.process:
                return
            if not self.status_bootstrap == 100:
                return
            self._controller = _Controller.from_port( port = self.config.control_port )
            self._controller.authenticate()
        elif not self._controller.is_alive():
            self._controller = None
            return self.controller
        return self._controller
    
    
    def _on_config_change( self , key , val ):
        key = "".join( k.capitalize() for k in key.split( "_" ) )
        if isinstance( val , int ):
            val = [ str( val ) ]
        if isinstance( val , list ):
            val = [ str( v ) for v in val ]
        try:
            self.controller.set_conf( key , val )
        except SocketClosed:
            self._controller = None
            self._on_config_change( key , val )
    
    
    @property
    def proxies( self ):
        
        def on_done_latency( task: asyncio.Task ):
            name = task.get_name()
            try:
                self._tasks.discard(task)
                proxy = task.result()
                if not proxy:
                    exc = task.exception()
                    raise exc
            except Exception as e:
                try:
                    
                    proxy = [ _ for _ in self._proxies if str( _.port ) == str( name ) ][ 0 ]
                    task = asyncio.ensure_future( PublicIPService.get_ip( proxy , timeout = 5 ) )
                    # print('RE ADDING TASK %s FOR PROXY %s' % (task, proxy))
                    task.set_name( proxy.port )
                    task.add_done_callback( on_done_latency )
                    
                    self._tasks.add( task )
                    return
                except IndexError:
                    pass
                except:
                    log.debug("on done latency - inner exception -  exception re-adding task", exc_info = True)
                
                # log.debug("on done latency - outer exception" , exc_info = True)
                
        
        # store the proxies in a local variable
        # so we can reuse them (and save on latency calcs)
        prxs = [ ]
        for p in self._proxies:
            prxs.append( p )
        self._proxies.clear()
        host = "127.0.0.1"
        
        if self.config:
            for port in self.config.socks_port:
                candidate = [ p for p in prxs if p.port == port ]
                if candidate:
                    proxy = candidate[ 0 ]
                elif isinstance( port , (str) ):
                    if ":" in port:
                        host , port = port.split( ":" )
                    proxy = SocksProxy( host = host , port = int( port ) )
                else:
                    proxy = SocksProxy( host = "127.0.0.1" , port = int( port ) )
                
                if not proxy.latency or not proxy.public_ip:
                    if not any([t.get_name() == str(proxy.port) for t in self._tasks]):
                    # if not proxy.port in self._tasks:
                        # only update latency/ip when not already scheduled
                        task = asyncio.ensure_future( PublicIPService.get_ip( proxy , timeout = 5 ) )
                        task.set_name(proxy.port)
                        task.add_done_callback( on_done_latency )
                        self._tasks.add(task)
                self._proxies.append( proxy )
        return self._proxies
    
    
    # @property
    # def proxies( self ):
    #     def on_done_latency( fut: asyncio.Future ):
    #         try:
    #             proxy = fut.result()
    #             if not proxy:
    #                 exc = fut._exception()
    #                 if exc:
    #                     self._tasks.clear()
    #                     raise exc
    #             self._tasks.pop( proxy.port )
    #         except Exception as e:
    #             print( e )
    #
    #
    #     # store the proxies in a local variable
    #     # so we can reuse them (and save on latency calcs
    #     prxs = [ ]
    #     for p in self._proxies:
    #         prxs.append( p )
    #     self._proxies.clear()
    #     host = "127.0.0.1"
    #
    #     if self.config:
    #         for port in self.config.socks_port:
    #             candidate = [ p for p in prxs if p.port == port ]
    #             if candidate:
    #                 proxy = candidate[ 0 ]
    #             elif isinstance( port , (str) ):
    #                 if ":" in port:
    #                     host , port = port.split( ":" )
    #                 proxy = SocksProxy( host = host , port = int( port ) )
    #             else:
    #                 proxy = SocksProxy( host = "127.0.0.1" , port = int( port ) )
    #             if not proxy.latency:
    #                 if not proxy.port in self._tasks:
    #                     task = asyncio.ensure_future( self._set_latency( proxy ) )
    #                     # proxy.port))
    #                     # task = asyncio.ensure_future(asyncio.to_thread(self._set_latency, proxy))
    #                     task.add_done_callback( on_done_latency )
    #                     self._tasks[ proxy.port ] = task
    #             self._proxies.append( proxy )
    #     return self._proxies
    
    def newnym( self ):
        if self.controller.get_newnym_wait() <= 0:
            self.controller.signal( _Signal.NEWNYM )
    
    def _clear_latency( self ):
        for _ in self.proxies:
            _._latency = None
    #
    # @staticmethod
    # async def _set_latency( proxy: SocksProxy ):
    #     cstart = time.perf_counter()
    #     reader , writer = await proxy.open_connection( host = "8.8.8.8" , port = 443 )
    #     # r , w = await open_connection(
    #     #     host = "8.8.8.8" , port = 443 , proxy_host = proxy.host , proxy_port = proxy.port
    #     #     )
    #     latency = time.perf_counter() - cstart
    #     # print('l', latency)
    #     proxy._latency = latency
    #     writer.close()
    #     await writer.wait_closed()
    #     # from requests import Session
    #     # s = Session()
    #     # proxy_url = str( proxy )
    #     # s.proxies = { 'http': proxy_url , 'https': proxy_url }
    #     # response = s.get( 'http://www.google.com' )
    #     # proxy.latency = response.elapsed.microseconds / 10 ** 6
    #     return proxy
    #
    
    def __repr__( self ):
        nports = ""
        if self.config and self.config.control_port:
            nports = f"socksports: {len( self.config.socks_port )}"
        return f"<{self.__class__.__name__} < running {self.running}, {nports} >"


class TorRC( dict ):
    
    
    def __init__(
            self ,
            socks_ports: list[ int ] = None ,
            control_port = 0 ,
            dns_port = 0 ,
            http_tunnel_port = 0 ,
            data_directory = "data" ,
            new_circuit_period = 15 ,
            cookie_authentication = 1 ,
            enforce_distinct_subnets = 0 ,
            hashed_control_password = "qwerty" ,
            ):
        self._notify_on_change = None

        socks_ports = socks_ports or [ DEFAULT_PORT ]

        if not isinstance( socks_ports , (list ,) ):
            socks_ports = [ socks_ports ]

        self.socks_port = socks_ports
        self.control_port = control_port or DEFAULT_PORT + 1
        self.dns_port = dns_port or DEFAULT_PORT + 2
        self.http_tunnel_port = http_tunnel_port or DEFAULT_PORT + 3
        self.data_directory = data_directory
        self.new_circuit_period = new_circuit_period
        self.cookie_authentication = cookie_authentication
        self.enforce_distinct_subnets = enforce_distinct_subnets
        # self.hashed_control_password = [
        #      hashed_control_password for n in range( len( self.socks_port ) )]
        #
        
        super().__init__( self.__dict__ )
        super().__setattr__( "__dict__" , self )
    
    
    def set_notify_on_change( self , callback ):
        self._notify_on_change = callback
    
    
    def __setattr__( self , key , value ):
        super().__setattr__( key , value )
        if key == "_notify_on_change":
            return
        if self._notify_on_change:
            self._notify_on_change( key , value )
    
    
    def as_cmdline( self ):
        cmdline = [ ]
        for key , value in self.items():
            if key[ 0 ] == "_":
                continue
            key = "".join( k.capitalize() for k in key.split( "_" ) )
            if isinstance( value , (str , int) ):
                cmdline.extend( [ f"--{key}" , f"{value}" ] )
            elif isinstance(
                    value ,
                    (
                            list ,
                            tuple ,
                            ) ,
                    ):
                for val in value:
                    cmdline.extend( [ f"--{key}" , f"{val}" ] )
            else:
                cmdline.extend( [ f"--{key}" , f"{str( value )}" ] )
        return cmdline
    
    
    def as_string( self ):
        """

        :return:
        """
        config_str = ""
        for key , value in self.items():
            if key[ 0 ] == "_":
                continue
            key = "".join( k.capitalize() for k in key.split( "_" ) )
            if isinstance( value , (str , int) ):
                config_str += f"{key} {value}\n"
            elif isinstance(
                    value ,
                    (
                            list ,
                            tuple ,
                            ) ,
                    ):
                for val in value:
                    config_str += f"{key} {val}\n"
            else:
                config_str += f"{key} {str( value )}\n"
        return config_str
    
    
    def as_bytes( self ):
        return self.as_string().encode( "utf-8" )


async def upgrade_stream_tls(
        reader: asyncio.StreamReader ,
        writer: asyncio.StreamWriter ,
        ssl_context: Optional[ ssl.SSLContext ] = None ,
        server_side: bool = False ,
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
            ssl_context = ssl.SSLContext( protocol = proto )
            ssl_context.load_verify_locations( certifi.where() )
            # ssl_context = ssl.create_default_context( ssl.Purpose.SERVER_AUTH )
    
    kwargs = dict(
        sslcontext = ssl_context ,
        server_side = server_side ,
    )
    if server_hostname:
        kwargs.update(dict(server_hostname=server_hostname))
    
    transport = writer.transport
    protocol = transport.get_protocol()
    loop = loop or asyncio.get_event_loop()
    new_transport = await loop.start_tls(
        transport = transport ,
        protocol = protocol ,
        **kwargs
        )
    
    setattr( reader , "_transport" , new_transport )
    setattr( writer , "_transport" , new_transport )
    # reader._transport = new_transport
    # writer._transport = new_transport


