import asyncio
import json
from loguru import logger
from lnbits.extensions.nostrwalletconnect.nostr.NostrClient import NostrClient
from lnbits.extensions.nostrwalletconnect.nostr.NostrEvent import NostrEvent
from lnbits.extensions.nostrclient.nostr.event import EventKind
from lnbits.extensions.nostrclient.nostr.key import PrivateKey

import secp256k1

import time

def sign_message_hash(private_key: str, hash: bytes) -> str:
    privkey = secp256k1.PrivateKey(bytes.fromhex(private_key))
    sig = privkey.schnorr_sign(hash, None, raw=True)
    return sig.hex()

async def subscribe_to_wallet_service_requests(nostr_client: NostrClient, wallet_connect_service_pubkey: str):
    # get env NOSTR_WALLET_CONNECT_PUBKEY value
    logger.info("Subscribing to wallet service requests")
    logger.info(f"Wallet service pubkey: {wallet_connect_service_pubkey}")

    await nostr_client.subscribe_wallet_connect_client_requests(wallet_connect_service_pubkey)

async def process_nostr_message( msg: str):
    try:
        type, *rest = json.loads(msg)

        if type.upper() == "EVENT":
            _, event = rest
            event = NostrEvent(**event)
            if event.kind == EventKind.WALLET_CONNECT_REQUEST:
            #     TODO: raise an asyncio event and somehow pay the invoice......
            return

    except Exception as ex:
        logger.debug(ex)

async def wait_for_nostr_events(nostr_client: NostrClient, wallet_connect_service_pubkey: str):
    await subscribe_to_wallet_service_requests(nostr_client, wallet_connect_service_pubkey)

    while True:
        message = await nostr_client.get_event()
        logger.info(f"Received message: {message}")
        await process_nostr_message(message)

def get_service_capabilities_event(private_key_hex: str):
    pk = bytes.fromhex(private_key_hex)
    private_key = PrivateKey(pk)
    public_key_hex = private_key.public_key.hex()

    event = NostrEvent(
        pubkey=public_key_hex,
        created_at=round(time.time()),
        kind=EventKind.WALLET_CONNECT_INFO,
        content="pay_invoice"
    )
    event.id = event.event_id

    event.sig = sign_message_hash(private_key_hex, bytes.fromhex(event.id))

    logger.info(f"Capabilities event: {event.dict()}")

    return event