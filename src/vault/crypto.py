"""Chiffrement du coffre : scrypt pour dériver la clé, AES-256-GCM pour chiffrer."""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Paramètres scrypt : coût élevé pour ralentir les tentatives hors ligne.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12

# Lié aux données chiffrées : un fichier d'une autre version ne se déchiffre pas.
ASSOCIATED_DATA = b"vault-v1"


class WrongPassword(Exception):
    """Mot de passe incorrect ou fichier altéré."""


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: bytes, password: str) -> dict[str, str]:
    """Chiffre `plaintext` et renvoie un dictionnaire sérialisable en JSON."""
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, ASSOCIATED_DATA)
    return {
        "v": 1,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "ct": _b64(ciphertext),
    }


def decrypt(blob: dict[str, str], password: str) -> bytes:
    """Déchiffre un blob produit par `encrypt`. Lève `WrongPassword` si la clé ne correspond pas."""
    try:
        salt = _unb64(blob["salt"])
        nonce = _unb64(blob["nonce"])
        ciphertext = _unb64(blob["ct"])
    except (KeyError, ValueError) as exc:
        raise WrongPassword("Fichier de coffre invalide") from exc
    key = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, ASSOCIATED_DATA)
    except InvalidTag as exc:
        raise WrongPassword("Mot de passe incorrect") from exc


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)
