import asyncio
import json
from loguru import logger
from lnbits.extensions.nostrwalletconnect.nostr.NostrClient import NostrClient
from lnbits.extensions.nostrwalletconnect.nostr.NostrEvent import NostrEvent
from lnbits.extensions.nostrclient.nostr.event import EventKind
from lnbits.extensions.nostrclient.nostr.key import PrivateKey

from lnbits.extensions.nostrwalletconnect.helpers import (
    build_encrypted_event,
    encrypt_event
)

from lnbits.nostrhelpers import (
    decrypt_message,
    get_shared_secret
)


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


async def process_nostr_message(nostr_client: NostrClient, msg: str, private_key_hex: str):
    try:
        type, *rest = json.loads(msg)

        logger.info(f"Processing message: {msg}")

        if type.upper() == "EVENT":
            _, event = rest
            event = NostrEvent(**event)
            if event.kind == EventKind.WALLET_CONNECT_REQUEST:
                await handle_pay_invoice_request(nostr_client, private_key_hex, event)
            return

    except Exception as ex:
        logger.info(ex)


async def handle_pay_invoice_request(nostr_client: NostrClient, private_key_hex: str, request_event: NostrEvent):
    # log event, private key hex and event pk
    logger.info(f"Event: {request_event.dict()}")
    logger.info(f"Private key hex: {private_key_hex}")
    logger.info(f"Event pk: {request_event.pubkey}")
    encryption_key = get_shared_secret(private_key_hex, request_event.pubkey)
    request_message_str = decrypt_message(request_event.content, encryption_key)
    # message is a json string, turn into an object
    request_message = json.loads(request_message_str)
    invoice = request_message["params"]["invoice"]
    # TODO: get actual wallet ID from DB based on secret used in request
    # TODO: create invoice_paid nostr response with payment_hash checking_id and other details
    pay_invoice_response_json = await pay_invoice(
        wallet_id="17332400405747fb9736ee418a52a09e",
        payment_request=invoice,
        description="Nostr Wallet Connect payment",
        extra={"tag": "nostrwalletconnect"},
        return_json=True
    )
    pay_invoice_response = json.loads(pay_invoice_response_json)
    response = {
        "result_type": "pay_invoice",
        "result": {
            "preimage": pay_invoice_response['preimage'],
        }
    }
    response_str = json.dumps(response)
    logger.info(f"Response: {response_str}")

    pk = bytes.fromhex(private_key_hex)
    private_key = PrivateKey(pk)
    wallet_connect_service_pubkey = private_key.public_key.hex()
    logger.info(f"Wallet connect service pubkey: {wallet_connect_service_pubkey}")

    response_event = NostrEvent(
        pubkey=wallet_connect_service_pubkey,
        created_at=round(time.time()),
        kind=EventKind.WALLET_CONNECT_RESPONSE,
        tags=[["e", request_event.id]],
        content=response_str
    )
    logger.info(f"e = {request_event.id}")
    # response_event.tags = {"e": request_event.id}
    encrypted_response_event = encrypt_event(response_event, private_key_hex)
    logger.info(f"Response event: {response_event.dict()}")
    logger.info(f"Encrypted response event: {encrypted_response_event.dict()}")
    await nostr_client.publish_nostr_event(encrypted_response_event)

    return


async def wait_for_nostr_events(nostr_client: NostrClient, wallet_connect_service_prviate_key: str):
    # derive pk
    pk = bytes.fromhex(wallet_connect_service_prviate_key)
    private_key = PrivateKey(pk)
    wallet_connect_service_pubkey = private_key.public_key.hex()
    await subscribe_to_wallet_service_requests(nostr_client, wallet_connect_service_pubkey)

    while True:
        message = await nostr_client.get_event()
        logger.info(f"Received message: {message}")
        await process_nostr_message(nostr_client, message, wallet_connect_service_prviate_key)


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
    logger.debug(f"Capabilities event: {event.dict()}")

    return event
