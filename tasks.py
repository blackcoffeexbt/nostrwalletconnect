import asyncio
import json
from loguru import logger
from lnbits.extensions.nostrwalletconnect.nostr.NostrClient import NostrClient
from lnbits.extensions.nostrwalletconnect.nostr.NostrEvent import NostrEvent
from lnbits.extensions.nostrclient.nostr.event import EventKind
from lnbits.extensions.nostrclient.nostr.key import PrivateKey

from lnbits.extensions.nostrwalletconnect.helpers import decrypt_message, get_shared_secret

from lnbits.core.services import pay_invoice

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

async def process_nostr_message( msg: str, private_key_hex: str):
    try:
        type, *rest = json.loads(msg)

        logger.info(f"Processing message: {msg}")

        if type.upper() == "EVENT":
            _, event = rest
            event = NostrEvent(**event)
            if event.kind == EventKind.WALLET_CONNECT_REQUEST:
                encryption_key = get_shared_secret(private_key_hex, event.pubkey)
                message_str = decrypt_message(event.content, encryption_key)
                logger.info(f"Decrypted message: {message_str}")
                # message is a json string, turn into an object
                message = json.loads(message_str)
                invoice = message["params"]["invoice"]
                logger.info(f"Received invoice: {invoice}")
                # TODO: get actual wallet ID from DB based on secret used in request
                # WHY ISNT THIS BEING CALLLED??!!
                payment_hash = await pay_invoice(
                    wallet_id="17332400405747fb9736ee418a52a09e",
                    payment_request=invoice,
                    description="Nostr Wallet Connect payment",
                    extra={"tag": "nostrwalletconnect"},
                    )
                # TODO: create invoice_paid nostr response with payment_hash checking_id and other details
                logger.info(f"Paid. Payment hash: {payment_hash}")
            return

    except Exception as ex:
        logger.info(ex)

async def wait_for_nostr_events(nostr_client: NostrClient, wallet_connect_service_prviate_key: str):
    # derive pk
    pk = bytes.fromhex(wallet_connect_service_prviate_key)
    private_key = PrivateKey(pk)
    wallet_connect_service_pubkey = private_key.public_key.hex()
    await subscribe_to_wallet_service_requests(nostr_client, wallet_connect_service_pubkey)

    while True:
        message = await nostr_client.get_event()
        logger.info(f"Received message: {message}")
        await process_nostr_message(message, wallet_connect_service_prviate_key)

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