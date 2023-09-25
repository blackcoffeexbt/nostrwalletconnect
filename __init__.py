import asyncio
import json

from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles

from typing import List

from asyncio import Task

from lnbits.extensions.nostrclient.nostr.key import PrivateKey

from loguru import logger

from lnbits.extensions.nostrwalletconnect.nostr.NostrClient import NostrClient
from lnbits.extensions.nostrwalletconnect.nostr.NostrEvent import NostrEvent

from lnbits.db import Database
from lnbits.helpers import template_renderer
from lnbits.settings import settings

db = Database("ext_nostrwalletconnect")

nostrwalletconnect_ext: APIRouter = APIRouter(prefix="/nostrwalletconnect", tags=["nostrwalletconnect"])

nostrwalletconnect_static_files = [
    {
        "path": "/nostrwalletconnect/static",
        "app": StaticFiles(packages=[("lnbits", "extensions/nostrwalletconnect/static")]),
        "name": "nostrwalletconnect_static",
    }
]

def nostrwalletconnect_renderer():
    return template_renderer(["lnbits/extensions/nostrwalletconnect/templates"])


from .views import *  # noqa: F401,F403
from .views_api import *  # noqa: F401,F403
from .tasks import *



def nostrwalletconnect_start():
    from lnbits.tasks import catch_everything_and_restart
    from lnbits.app import settings

    # TODO: un-hardcode this
    wallet_connect_secret = "362805b0d6ebec963f098ca849e7228d4ece39d970d8f97af5bdccdecdc80ea1"

    nostr_client = NostrClient()

    scheduled_tasks: List[Task] = []

    secret = settings.nostr_wallet_connect_secret
    service_privkey_hex = "bdd19cecd942ed8964c2e0ddc92d5e09838d3a09ebb230d974868be00886704b"
    pk = bytes.fromhex(service_privkey_hex)
    private_key = PrivateKey(pk)
    service_pubkey_hex = private_key.public_key.hex()

    # every time lnbits starts, we need to send an info event to relays to inform the relay of
    # the wallet connect service's capabilities
    capabilities_event = get_service_capabilities_event(service_pubkey_hex)

    async def _publish_capabilities_event():
        await nostr_client.publish_nostr_event(capabilities_event)

    async def _subscribe_to_nostr_request():
        # wait for 'nostrclient' extension to initialize
        await asyncio.sleep(10)
        await nostr_client.run_forever()
        raise ValueError("Must reconnect to websocket")

    async def _wait_for_nostr_events():
        # wait for this extension to initialize
        await asyncio.sleep(15)
        await wait_for_nostr_events(nostr_client, service_privkey_hex)
        # wait for asyncio event

        # await asyncio.sleep(15)
        # await _publish_capabilities_event()

    loop = asyncio.get_event_loop()
    task1 = loop.create_task(catch_everything_and_restart(_subscribe_to_nostr_request))
    task2 = loop.create_task(catch_everything_and_restart(_wait_for_nostr_events))
    scheduled_tasks.extend([task1, task2])