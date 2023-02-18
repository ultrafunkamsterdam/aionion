▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░████████╗░██████╗░██████╗░░█████╗░██╗░██████╗░░
░╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗██║██╔═══██╗░
░░░░██║░░░██║░░░██║██████╔╝███████║██║██║░░░██║░
░░░░██║░░░██║░░░██║██╔══██╗██╔══██║██║██║░░░██║░
░░░░██║░░░╚██████╔╝██║░░██║██║░░██║██║╚██████╔╝░
░░░░╚═╝░░░░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░╚═════╝░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒

toraio - a pool of proxies, shifting on each request
======================

What?
----
using toraio you can easily create a small pool of
tor proxies so you can take advantage of having multiple 
circuits at your disposal and multiple ip addresses, while
running just 1 process. It also brings a ClientSession, which
is the ClientSession from aiohttp with a small modification:
it shifts proxies at every request. 


Does it work for **requests** package? and **urllib**? and plain **sockets** ?
-----
yes! toraio.Pool() is a context manager which, while in context, patches
the low level socket library, so it's usage is easy and compatible for almost 
all setups/libraries.


Cleaning up
------
Pool will automatically cleanup the temp folder after your program ends.
the folder is needed for tor to store circuit and consensus data.
if you specify a folder explicitly, like Pool(user_data_dir="c:\\some\\folder\\tordata"),
it is assumed you want a dedicated folder. in that case cleanup will not happen. 
using a dedicated folder will greatly improve loading time on next runs. 


It is blocking!
----
only once!
toraio should ideally be started on your mainthread. it will block 
to bootstrap the tor connections, and this only happens once during 
the full lifecycle of your program.
while subprocesses are supported by asyncio, it would render useless 
as proxies can't be used anyway, until initialization is finished.
It also brings a lot of other unexpected behavior.


toraio.Pool is a true singleton. Every Pool() you create
will refer to the **same** instance. If you need more proxies,
just use the amount parameter (defaults to 10, which is 
more than sufficient, and actually too much). 


proxies in the pool are refreshed at least once 15 minutes, getting
new circuits from different countries, and new ip's. 




Why another library around Onion/Tor?
----
for most people, setting up tor is already quite a task,
implementing them as proxies in their programs requires much
more work. the purpose of toraio is to make it as easy
as it can possibly get. 

Show me how easy it is!
----
```python
import logging
import asyncio
import toraio

async def main():
    async with toraio.ClientSession() as session:
        for _ in range(10):
            async with session.get('http://httpbin.org/ip') as response:
                print ( await response.json() )


logging.basicConfig(level=10)
asyncio.run(main())
```

this will output
```
DEBUG:asyncio:Using proactor: IocpProactor
INFO:pool:starting proxy pool 0x2a214dc9be0
INFO:pool:tor bootstrap 0.0 completed
INFO:pool:tor bootstrap 5.0 completed
INFO:pool:tor bootstrap 10.0 completed
INFO:pool:tor bootstrap 14.0 completed
INFO:pool:tor bootstrap 15.0 completed
INFO:pool:tor bootstrap 20.0 completed
INFO:pool:tor bootstrap 25.0 completed
INFO:pool:tor bootstrap 30.0 completed
INFO:pool:tor bootstrap 40.0 completed
INFO:pool:tor bootstrap 45.0 completed
INFO:pool:tor bootstrap 50.0 completed
INFO:pool:tor bootstrap 55.0 completed
INFO:pool:tor bootstrap 60.0 completed
INFO:pool:tor bootstrap 68.0 completed
INFO:pool:tor bootstrap 75.0 completed
INFO:pool:tor bootstrap 80.0 completed
INFO:pool:tor bootstrap 85.0 completed
INFO:pool:tor bootstrap 89.0 completed
INFO:pool:tor bootstrap 90.0 completed
INFO:pool:tor bootstrap 95.0 completed
INFO:pool:tor bootstrap 100.0 completed

DEBUG:toraio._client_session:proxy switched
{'origin': '109.70.100.32'}
DEBUG:toraio._client_session:proxy switched
{'origin': '107.189.31.241'}
DEBUG:toraio._client_session:proxy switched
{'origin': '89.163.143.8'}
DEBUG:toraio._client_session:proxy switched
{'origin': '45.153.160.133'}
DEBUG:toraio._client_session:proxy switched
{'origin': '104.244.75.33'}
DEBUG:toraio._client_session:proxy switched
{'origin': '199.249.230.187'}
DEBUG:toraio._client_session:proxy switched
{'origin': '185.220.102.245'}
DEBUG:toraio._client_session:proxy switched
{'origin': '213.61.215.54'}
DEBUG:toraio._client_session:proxy switched
{'origin': '193.189.100.199'}
DEBUG:toraio._client_session:proxy switched
{'origin': '176.10.99.200'}

```

Lets run this again
```python
asyncio.run(main())
```

```
# no initialization is done
# it returns immediately 

DEBUG:toraio._client_session:proxy switched
{'origin': '109.70.100.32'}
DEBUG:toraio._client_session:proxy switched
{'origin': '107.189.31.241'}
DEBUG:toraio._client_session:proxy switched
{'origin': '89.163.143.8'}
DEBUG:toraio._client_session:proxy switched
{'origin': '45.153.160.133'}
DEBUG:toraio._client_session:proxy switched
{'origin': '104.244.75.33'}
DEBUG:toraio._client_session:proxy switched
{'origin': '199.249.230.187'}
DEBUG:toraio._client_session:proxy switched
{'origin': '185.220.102.245'}
DEBUG:toraio._client_session:proxy switched
{'origin': '213.61.215.54'}
DEBUG:toraio._client_session:proxy switched
{'origin': '193.189.100.199'}
DEBUG:toraio._client_session:proxy switched
{'origin': '176.10.99.200'}

```

Showing different ways to get a pool and showing how to use the pool as context manager
```python
import toraio

pool = toraio.start()   # this gives you a running pool

pool2 = toraio.Pool()   # this gives you the same pool (because singleton) if already bootstrapped

pool2.start()           # will start and bootstrap the pool, if not already running
                        # start() has the pool itself as return value

pool3 = toraio.Pool.get_instance()  # same story

pool4 = toraio.start()   # same story


import requests

# context manager

with pool:       
    # in this block, all network will be handled by the proxies and it will return 
    # different ip's on subsequent calls
    print(requests.get('http://httpbin.org/ip').text)

# not in context
# you will see your own ip
print(requests.get('http://httpbin.org/ip').text)



```