import base64
import json
import secrets
from typing import Any, Optional, Tuple

import time

from lnbits.extensions.nostrwalletconnect.nostr.NostrEvent import NostrEvent
from lnbits.extensions.nostrclient.nostr.event import EventKind

from lnbits.nostrhelpers import sign_message_hash

from lnbits.nostrhelpers import (
    encrypt_message,
    derive_public_key
)

from loguru import logger

import secp256k1
from cffi import FFI
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def get_shared_secret(privkey: str, pubkey: str):
    point = secp256k1.PublicKey(bytes.fromhex("02" + pubkey), True)
    return point.ecdh(bytes.fromhex(privkey), hashfn=copy_x)


def sign_message_hash(private_key: str, hash: bytes) -> str:
    privkey = secp256k1.PrivateKey(bytes.fromhex(private_key))
    sig = privkey.schnorr_sign(hash, None, raw=True)
    return sig.hex()

def encrypt_event(event: NostrEvent, from_privkey: str) -> NostrEvent:
    encryption_key = get_shared_secret(from_privkey, event.pubkey)
    content = encrypt_message(event.content, encryption_key)
    event.content = content
    event.id = event.event_id
    event.sig = sign_message_hash(from_privkey, bytes.fromhex(event.id))
    return event


def build_encrypted_event(message: str, from_privkey: str, to_pubkey: str,
                          event_type: EventKind) -> NostrEvent:
    encryption_key = get_shared_secret(from_privkey, to_pubkey)
    content = encrypt_message(message, encryption_key)
    this_pubkey = derive_public_key(from_privkey)
    event = NostrEvent(
        pubkey=this_pubkey,
        created_at=round(time.time()),
        kind=event_type,
        tags=[["p", to_pubkey]],
        content=content,
    )
    event.id = event.event_id
    event.sig = sign_message_hash(from_privkey, bytes.fromhex(event.id))

    return event


ffi = FFI()


@ffi.callback(
    "int (unsigned char *, const unsigned char *, const unsigned char *, void *)"
)
def copy_x(output, x32, y32, data):
    ffi.memmove(output, x32, 32)
    return 1


def order_from_json(s: str) -> Tuple[Optional[Any], Optional[str]]:
    try:
        order = json.loads(s)
        return (order, s) if (type(order) is dict) and "items" in order else (None, s)
    except ValueError:
        return None, s
