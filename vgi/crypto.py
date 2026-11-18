"""Signing primitives for the platform.

We use Ed25519 so that the authorization domain can *issue* (sign) grants
while the execution and evidence domains can only *verify* them. The private
signing key never leaves the domain that owns it; everyone else holds only a
public verify key. This is what makes "separate credentials" a real boundary
rather than a naming convention.

The whole module is intentionally thin: a KeyPair, a VerifyKey, a canonical
`sign`/`verify` over bytes, and a stable `key_id`. No key material is ever
logged or serialized except the public key.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NO_ENC = serialization.NoEncryption()


def _pub_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(_RAW, _RAW_PUB)


def key_id(pub: Ed25519PublicKey) -> str:
    """Stable short identifier for a public key (first 16 bytes of SHA-256)."""
    return hashlib.sha256(_pub_raw(pub)).hexdigest()[:32]


@dataclass(frozen=True)
class VerifyKey:
    """A public verify key. Cannot sign; can only check signatures."""

    _pub: Ed25519PublicKey

    @property
    def key_id(self) -> str:
        return key_id(self._pub)

    def verify(self, message: bytes, signature_hex: str) -> bool:
        try:
            self._pub.verify(bytes.fromhex(signature_hex), message)
            return True
        except (InvalidSignature, ValueError):
            return False

    def to_hex(self) -> str:
        return _pub_raw(self._pub).hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> "VerifyKey":
        return cls(Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str)))


class KeyPair:
    """A private signing key held by exactly one trust domain."""

    def __init__(self, priv: Ed25519PrivateKey):
        self._priv = priv

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_hex(cls, hex_str: str) -> "KeyPair":
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str)))

    def sign(self, message: bytes) -> str:
        return self._priv.sign(message).hex()

    @property
    def verify_key(self) -> VerifyKey:
        return VerifyKey(self._priv.public_key())

    @property
    def key_id(self) -> str:
        return self.verify_key.key_id

    def private_hex(self) -> str:
        """Export the private key. Used only to persist a domain's own key."""
        return self._priv.private_bytes(_RAW, _RAW_PRIV, _NO_ENC).hex()
