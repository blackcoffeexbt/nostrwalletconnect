import asyncio
import hashlib
import json

import time

from websocket import WebSocketApp

from asyncio import Queue
from threading import Thread

from loguru import logger

from typing import AsyncGenerator, Dict, Optional, List, Callable

from lnbits.extensions.nostrwalletconnect.nostr.NostrEvent import NostrEvent

from lnbits.extensions.nostrclient.nostr.event import EventKind

from lnbits.settings import settings
from lnbits.helpers import urlsafe_short_hash

class NostrClient:
    def __init__(self):
        self.recieve_event_queue: Queue = Queue()
        self.send_req_queue: Queue = Queue()
        self.ws: WebSocketApp = None
        self.subscription_id = "nostrmarket-" + urlsafe_short_hash()[:32]

    async def connect_to_nostrclient_ws(
            self, on_open: Callable, on_message: Callable
    ) -> WebSocketApp:
        def on_error(_, error):
            logger.warning(error)

        logger.info(f"Subscribing to websockets for nostrclient extension")
        ws = WebSocketApp(
            f"ws://localhost:{settings.port}/nostrclient/api/v1/relay",
            # "wss://nostr-pub.wellorder.net",
            on_message=on_message,
            on_open=on_open,
            on_error=on_error,
        )

        wst = Thread(target=ws.run_forever)
        wst.daemon = True
        wst.start()

        return ws

    async def get_event(self):
        value = await self.recieve_event_queue.get()
        if isinstance(value, ValueError):
            raise value
        return value

    async def run_forever(self):
        def on_open(_):
            logger.info("Connected to 'nostrclient' websocket")

        def on_message(_, message):
            self.recieve_event_queue.put_nowait(message)

        running = True

        while running:
            try:
                req = None
                if not self.ws:
                    self.ws = await self.connect_to_nostrclient_ws(on_open, on_message)
                    # be sure the connection is open
                    await asyncio.sleep(3)
                req = await self.send_req_queue.get()

                if isinstance(req, ValueError):
                    running = False
                    logger.warning(str(req))
                else:
                    logger.info(f"Sending request: {req}")
                    self.ws.send(json.dumps(req))
            except Exception as ex:
                logger.warning(ex)
                if req:
                    await self.send_req_queue.put(req)
                self.ws = None  # todo close
                await asyncio.sleep(5)

    async def publish_nostr_event(self, e: NostrEvent):
        await self.send_req_queue.put(["EVENT", e.dict()])

    async def subscribe_wallet_connect_client_requests(
            self,
            wallet_service_pubkey: str,
    ):
        dm_time = int(time.time())
        request_filters = self._filters_for_service_request_messages(wallet_service_pubkey, dm_time)

        self.subscription_id = "nostrwalletconnect-" + urlsafe_short_hash()[:32]
        await self.send_req_queue.put(["REQ", self.subscription_id] + request_filters)
        # log dm_filters
        logger.debug(request_filters)

        logger.info(
            f"Subscribed to events for: {wallet_service_pubkey} keys. New subscription id: {self.subscription_id}"
        )

    def _filters_for_service_request_messages(self, wallet_service_pubkey: str, since: int) -> List:
        out_messages_filter = {"kinds": [EventKind.WALLET_CONNECT_REQUEST], "#p": wallet_service_pubkey}
        if since and since != 0:
            out_messages_filter["since"] = since

        return [out_messages_filter]

    async def restart(self):
        await self.unsubscribe_merchants()
        # Give some time for the CLOSE events to propagate before restarting
        await asyncio.sleep(10)

        logger.info("Restating NostrClient...")
        await self.send_req_queue.put(ValueError("Restarting NostrClient..."))
        await self.recieve_event_queue.put(ValueError("Restarting NostrClient..."))

        self.ws.close()
        self.ws = None

    async def stop(self):
        await self.unsubscribe_merchants()

        # Give some time for the CLOSE events to propagate before closing the connection
        await asyncio.sleep(10)
        self.ws.close()
        self.ws = None

    async def unsubscribe(self, subscription_id):
        await self.send_req_queue.put(["CLOSE", subscription_id])
        logger.debug(f"Unsubscribed from subscription id: {subscription_id}")