▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░  █████╗ ██╗ ██████╗ ███╗   ██╗██╗ ██████╗ ███╗   ██╗ ░░
░░ ██╔══██╗██║██╔═══██╗████╗  ██║██║██╔═══██╗████╗  ██║ ░░
░░ ███████║██║██║   ██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║ ░░
░░ ██╔══██║██║██║   ██║██║╚██╗██║██║██║   ██║██║╚██╗██║ ░░
░░ ██║  ██║██║╚██████╔╝██║ ╚████║██║╚██████╔╝██║ ╚████║ ░░
░░ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ░░                                                
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒

aionion - a pool of proxies, shifting on each request
======================

What?
----
using aionion you can easily create a small pool of
tor proxies so you can take advantage of having multiple 
circuits at your disposal and multiple ip addresses, while
running just 1 process. It also brings a ClientSession, which
is the ClientSession from aiohttp, and RequestsSession which resembles the 
Session from the requests package, with a small modification:
it shifts proxies at every request. 


Cleaning up
------



Something
----


Some more
----



Why another library around Onion/Tor?
----
for most people, setting up tor is already quite a task,
implementing them as proxies in their programs requires much
more work. the purpose of aionion is to make it as easy
as it can possibly get. 

Show me how easy it is!
----
```python
import logging
import asyncio
import aionion

async def main():
    tor = await aionion.create_async(10)
    async with aionion.ClientSession(tor) as session:
        for _ in range(10):
            async with session.get('http://httpbin.org/ip') as response:
                print ( await response.json() )


logging.basicConfig(level=10)
asyncio.run(main())
```


Lets run this again
```python
asyncio.run(main())
```
