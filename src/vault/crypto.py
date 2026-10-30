"""Chiffrement du coffre : scrypt pour dériver la clé, AES-256-GCM pour chiffrer.

Format v2 : les paramètres scrypt sont écrits dans le fichier et liés aux données chiffrées
(données associées). Les modifier fait donc échouer le déchiffrement. Le format v1 reste lisible.
"""

from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT_VERSION = 2

# Paramètres scrypt utilisés à l'écriture : coût élevé pour ralentir les tentatives hors ligne.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

# Bornes vérifiées à la lecture : un fichier altéré ne doit pas faire exploser la mémoire.
MIN_SCRYPT_N = 2**10
MAX_SCRYPT_N = 2**20
MAX_SCRYPT_R = 32
MAX_SCRYPT_P = 16

KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12

# Format v1 (lecture seule) : paramètres fixes, données associées propres à la version.
_V1_N = 2**15
_V1_R = 8
_V1_P = 1
_V1_ASSOCIATED = b"vault-v1"


class WrongPassword(Exception):
    """Mot de passe incorrect ou fichier altéré."""


def derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def _associated_data(n: int, r: int, p: int) -> bytes:
    return f"vault-v{FORMAT_VERSION}:n={n}:r={r}:p={p}".encode("ascii")


def encrypt(plaintext: bytes, password: str) -> dict[str, Any]:
    """Chiffre `plaintext` et renvoie un dictionnaire sérialisable en JSON."""
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = derive_key(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    ad = _associated_data(SCRYPT_N, SCRYPT_R, SCRYPT_P)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, ad)
    return {
        "v": FORMAT_VERSION,
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "ct": _b64(ciphertext),
    }


def decrypt(blob: dict[str, Any], password: str) -> bytes:
    """Déchiffre un blob produit par `encrypt`. Lève `WrongPassword` si la clé ne correspond pas."""
    try:
        version = blob.get("v")
        salt = _unb64(blob["salt"])
        nonce = _unb64(blob["nonce"])
        ciphertext = _unb64(blob["ct"])
        if version == 1:
            n, r, p = _V1_N, _V1_R, _V1_P
            ad = _V1_ASSOCIATED
        elif version == FORMAT_VERSION:
            n, r, p = int(blob["n"]), int(blob["r"]), int(blob["p"])
            _check_params(n, r, p)
            ad = _associated_data(n, r, p)
        else:
            raise WrongPassword("Version de coffre inconnue")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise WrongPassword("Fichier de coffre invalide") from exc

    key = derive_key(password, salt, n, r, p)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, ad)
    except (InvalidTag, ValueError) as exc:
        raise WrongPassword("Mot de passe incorrect") from exc


def _check_params(n: int, r: int, p: int) -> None:
    if not (MIN_SCRYPT_N <= n <= MAX_SCRYPT_N and n & (n - 1) == 0):
        raise ValueError("coût scrypt hors limites")
    if not (1 <= r <= MAX_SCRYPT_R and 1 <= p <= MAX_SCRYPT_P):
        raise ValueError("paramètres scrypt hors limites")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)
