import logging
from . import utils
from .tor import *
from .integrations import ClientSession, ClientResponse, ClientRequest, RequestsSession

logger = logging.getLogger(__name__)


def get_running_instance():
    from . import tor

    return tor.INSTANCES


def set_loglevel(level=30):
    """
    enables debug mode. which includes LOTS of logging
    """
    from . import tor

    logger.setLevel(level)


def set_default_limit(default=2**16):
    tor.DEFAULT_LIMIT = default


def set_default_port(default=10080):
    tor.DEFAULT_PORT = default


def create_in_background_sync(nproxies=10) -> "Tor":
    """
    spins up a background thread which handles the startup
    and keep-alive of the process.
    ensure to assign this to a variable!

    :param nproxies: (int) number of initial proxies (default=10) which is more than enough

    example:
        tor = create_in_background_sync()

    """
    from . import utils
    from . import tor

    t = tor.Tor(nproxies)
    bgt = utils.run_in_background_thread(t)
    # ugly workaround
    logger.debug(str(t.proxies))  # =property -> makes sure proxies are intitialized
    return t


async def create_async(nproxies=10) -> "Tor":
    """
    async function
    returns a running ```tor.Tor``` instance, unless there is an error.
    make sure you assign this to a variable!

    :param nproxies: (int) number of initial proxies (default=10) which is more than enough

    example:
        tor = await create_async()
    """
    from . import tor

    t = tor.Tor(nproxies)
    return await t.start()
