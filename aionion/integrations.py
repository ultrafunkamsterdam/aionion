import asyncio
import itertools
from itertools import cycle
import json
import logging
from ssl import SSLContext
from types import SimpleNamespace
from typing import Any
from typing import Callable
from typing import IO
from typing import Iterable
from typing import List
from typing import Mapping
from typing import MutableMapping
from typing import Optional
from typing import Text
from typing import Tuple
from typing import Type
from typing import Union

from aiohttp import BasicAuth
from aiohttp import ClientRequest as ClientRequest
from aiohttp import ClientResponse
from aiohttp import ClientTimeout
from aiohttp import ClientWebSocketResponse as ClientWebSocketResponse
from aiohttp import Fingerprint
from aiohttp import HttpVersion
from aiohttp import HttpVersion11
from aiohttp import TraceConfig
from aiohttp.abc import AbstractCookieJar
from aiohttp.client import ClientSession as _ClientSession
from aiohttp.helpers import sentinel
from aiohttp.typedefs import JSONEncoder
from aiohttp.typedefs import LooseCookies
from aiohttp.typedefs import LooseHeaders
from aiohttp.typedefs import StrOrURL
from aiohttp_socks.connector import ProxyConnector as _ProxyConnector
from aiohttp_socks.connector import ProxyType as _ProxyType
import requests.auth

from aionion.tor import Tor


log = logging.getLogger(__name__)

__all__ = ["log", "ClientSession", "RequestsSession", "ClientRequest", "ClientResponse"]


def __getattr__(name):
    if name not in __all__:
        raise AttributeError(name)


class ProxyConnectTor(_ProxyConnector):
    @property
    def proxy(self):
        return self._proxy

    def __init__(
        self, tor: Tor, rdns=None, force_close=True, use_dns_cache=False, **kwargs
    ):
        # create the generator from current proxies
        self.proxy_cycle = cycle(tor.proxies)

        # this is bogus to initialize the parent
        super().__init__(
            _ProxyType.SOCKS5,
            host=None,
            port=None,
            username=None,
            password=None,
            rdns=rdns,
            force_close=force_close,
            use_dns_cache=use_dns_cache,
            **kwargs
        )
        self._proxy = None

    def next_proxy(self):
        p = next(self.proxy_cycle)
        self._proxy_host, self._proxy_port = p
        self._proxy = p

    async def _wrap_create_connection(
        self, protocol_factory, host, port, *, ssl, **kwargs
    ):
        # get next proxy from generator and set it to proxy_host and proxy_port
        self.next_proxy()
        log.debug("using proxy %s for request" % (self.proxy))
        return await super()._wrap_create_connection(
            protocol_factory, host, port, ssl=ssl, **kwargs
        )

    @classmethod
    def from_url(cls, url, **kwargs):
        raise NotImplemented("from_url cannot be used in %s" % cls.__name__)


class ClientSession(_ClientSession):
    """
    Drop-in replacement for ```aiohttp.ClientSession```
    """

    def __init__(
        self,
        tor: Tor,
        base_url: Optional[StrOrURL] = None,
        *,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        cookies: Optional[LooseCookies] = None,
        headers: Optional[LooseHeaders] = None,
        skip_auto_headers: Optional[Iterable[str]] = None,
        auth: Optional[BasicAuth] = None,
        json_serialize: JSONEncoder = json.dumps,
        request_class: Type[ClientRequest] = ClientRequest,
        response_class: Type[ClientResponse] = ClientResponse,
        ws_response_class: Type[ClientWebSocketResponse] = ClientWebSocketResponse,
        version: HttpVersion = HttpVersion11,
        cookie_jar: Optional[AbstractCookieJar] = None,
        connector_owner: bool = True,
        raise_for_status: bool = False,
        read_timeout: Union[float, object] = sentinel,
        conn_timeout: Optional[float] = None,
        timeout: Union[object, ClientTimeout] = sentinel,
        auto_decompress: bool = True,
        trust_env: bool = False,
        requote_redirect_url: bool = True,
        trace_configs: Optional[List[TraceConfig]] = None,
        read_bufsize: int = 2**16
    ) -> None:
        # the missing parameter (connector) is being created here based on the provided Tor instance,  so it uses the correct proxies
        self.tor = tor
        connector = ProxyConnectTor(tor)

        super().__init__(
            base_url,
            connector=connector,
            loop=loop,
            cookies=cookies,
            headers=headers,
            skip_auto_headers=skip_auto_headers,
            auth=auth,
            json_serialize=json_serialize,
            request_class=request_class,
            response_class=response_class,
            ws_response_class=ws_response_class,
            version=version,
            cookie_jar=cookie_jar,
            connector_owner=connector_owner,
            raise_for_status=raise_for_status,
            read_timeout=read_timeout,
            conn_timeout=conn_timeout,
            timeout=timeout,
            auto_decompress=auto_decompress,
            trust_env=trust_env,
            requote_redirect_url=requote_redirect_url,
            trace_configs=trace_configs,
            read_bufsize=read_bufsize,
        )

    #
    # def __init__( self , tor: Tor , *args , **kwargs ):
    #     connector = ProxyConnectTor( tor )
    #     super().__init__( *args , connector = connector , **kwargs )
    #     self.tor = tor
    #

    async def _request(
        self,
        method: str,
        str_or_url: StrOrURL,
        *,
        params: Optional[Mapping[str, str]] = None,
        data: Any = None,
        json: Any = None,
        cookies: Optional[LooseCookies] = None,
        headers: Optional[LooseHeaders] = None,
        skip_auto_headers: Optional[Iterable[str]] = None,
        auth: Optional[BasicAuth] = None,
        allow_redirects: bool = True,
        max_redirects: int = 10,
        compress: Optional[str] = None,
        chunked: Optional[bool] = None,
        expect100: bool = False,
        raise_for_status: Optional[bool] = None,
        read_until_eof: bool = True,
        timeout: Union[ClientTimeout, object] = sentinel,
        verify_ssl: Optional[bool] = None,
        fingerprint: Optional[bytes] = None,
        ssl_context: Optional[SSLContext] = None,
        ssl: Optional[Union[SSLContext, bool, Fingerprint]] = None,
        trace_request_ctx: Optional[SimpleNamespace] = None,
        read_bufsize: Optional[int] = None,
        **kwargs
    ) -> ClientResponse:
        self.connector.next_proxy()
        proxy = self.connector.proxy
        resp = await super()._request(
            method,
            str_or_url,
            params=params,
            data=data,
            json=json,
            cookies=cookies,
            headers=headers,
            skip_auto_headers=skip_auto_headers,
            auth=auth,
            allow_redirects=allow_redirects,
            max_redirects=max_redirects,
            compress=compress,
            chunked=chunked,
            expect100=expect100,
            raise_for_status=raise_for_status,
            read_until_eof=read_until_eof,
            timeout=timeout,
            verify_ssl=verify_ssl,
            fingerprint=fingerprint,
            ssl_context=ssl_context,
            ssl=ssl,
            trace_request_ctx=trace_request_ctx,
            read_bufsize=read_bufsize,
            **kwargs
        )
        try:
            # add the used proxy to the response
            resp.proxy = proxy
        except:
            log.debug(
                "could not determine the proxy used for this request. error: ",
                exc_info=True,
            )
        return resp

    def __del__(self, _warnings: Any = None) -> None:
        super().__del__()


class RequestsSession(requests.Session):
    """
    Drop-in replacement for ```requests.Session``` for use with Aionion
    """

    def __init__(self, tor: Tor) -> None:
        self.proxy_cycle = itertools.cycle(tor.proxies)
        super().__init__()

    def request(
        self,
        method: str,
        url: Union[str, bytes, Text],
        params=None,
        data=None,
        headers: Optional[MutableMapping[Text, Text]] = None,
        cookies: Union[
            None, requests.sessions.RequestsCookieJar, MutableMapping[Text, Text]
        ] = None,
        files: Optional[MutableMapping[Text, IO[Any]]] = None,
        auth: Union[
            None,
            Tuple[Text, Text],
            requests.auth.AuthBase,
            Callable[
                [requests.sessions.PreparedRequest], requests.sessions.PreparedRequest
            ],
        ] = None,
        timeout: Union[None, float, Tuple[float, float], Tuple[float, None]] = None,
        allow_redirects: Optional[bool] = None,
        proxies=None,
        hooks=None,
        stream: Optional[bool] = None,
        verify: Union[None, bool, Text] = None,
        cert: Union[Text, Tuple[Text, Text], None] = None,
        json: Optional[Any] = None,
    ) -> requests.Response:
        proxy = next(self.proxy_cycle)
        proxies = {"http": proxy.socks_url, "https": proxy.socks_url}
        response = super().request(
            method,
            url,
            params,
            data,
            headers,
            cookies,
            files,
            auth,
            timeout,
            allow_redirects,
            proxies,  # here, the proxies defined above, are used
            hooks,
            stream,
            verify,
            cert,
            json,
        )
        try:
            # add the used proxy to the response
            response.proxy = proxy
        except:
            log.debug(
                "could not determine the proxy used for this request. error: ",
                exc_info=True,
            )
        return response
