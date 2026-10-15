"""Tiny CoAP device for the demo. Plaintext on UDP 5683, no authentication,
and it exposes one harmless resource and one that looks sensitive.
Loopback only."""
import asyncio
import aiocoap
import aiocoap.resource as resource


class Text(resource.Resource):
    # Returns a fixed text payload for GET requests.
    def __init__(self, body):
        super().__init__()
        self.body = body

    async def render_get(self, request):
        return aiocoap.Message(payload=self.body.encode())


async def main():
    root = resource.Site()
    # .well-known/core is the discovery document that both nmap scripts read.
    root.add_resource(['sensors', 'temp'], Text('24.5'))
    root.add_resource(['admin', 'config'], Text('device=demo;mode=open'))

    # aiocoap adds a few of its own links (a version link and /.well-known/core
    # itself). Keep only our two device paths so the scan output stays readable.
    def device_links():
        links = root.get_resources_as_linkheader()
        links.links = [l for l in links.links
                       if l.href in ('/sensors/temp', '/admin/config')]
        return links

    root.add_resource(['.well-known', 'core'], resource.WKCResource(device_links, impl_info=None))
    await aiocoap.Context.create_server_context(root, bind=('127.0.0.1', 5683))
    await asyncio.get_running_loop().create_future()  # run forever


asyncio.run(main())
