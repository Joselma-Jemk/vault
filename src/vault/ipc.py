"""Canal local entre la CLI et l'appli : un tube nommé Qt, une requête JSON par ligne.

Le serveur tourne dans l'appli déverrouillée. La CLI ne voit jamais de valeur :
elle envoie une demande, et reçoit seulement la réponse du courtier.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from PySide6.QtCore import QCoreApplication, QObject
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from vault.broker import Broker
from vault.paths import server_name

MAX_MESSAGE_BYTES = 64 * 1024
CLIENT_CONNECT_MS = 3_000
CLIENT_REPLY_MS = 130_000  # l'utilisateur dispose de 60 s pour approuver, plus la commande


class ServerUnavailable(Exception):
    """L'appli n'écoute pas : elle n'est pas ouverte, ou le coffre est verrouillé."""


class BrokerServer(QObject):
    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._broker: Broker | None = None
        self._server = QLocalServer(self)
        # Seul l'utilisateur Windows qui a lancé l'appli peut se connecter.
        self._server.setSocketOptions(QLocalServer.UserAccessOption)
        self._server.newConnection.connect(self._on_connection)

    def start(self) -> None:
        QLocalServer.removeServer(server_name())
        if not self._server.listen(server_name()):
            raise RuntimeError(f"Canal local indisponible : {self._server.errorString()}")

    def stop(self) -> None:
        self._broker = None
        self._server.close()

    def set_broker(self, broker: Broker | None) -> None:
        """Branché au déverrouillage, débranché au verrouillage."""
        self._broker = broker

    def _on_connection(self) -> None:
        socket = self._server.nextPendingConnection()
        if socket is None:
            return
        data = bytearray()
        while b"\n" not in data and len(data) <= MAX_MESSAGE_BYTES:
            if not socket.waitForReadyRead(5_000):
                break
            data += bytes(socket.readAll())
        response = self._respond(bytes(data))
        socket.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
        socket.flush()
        socket.waitForBytesWritten(3_000)
        socket.disconnectFromServer()

    def _respond(self, raw: bytes) -> dict[str, Any]:
        if self._broker is None:
            return {"ok": False, "error": "Coffre verrouillé : ouvre l'application et déverrouille-le"}
        if len(raw) > MAX_MESSAGE_BYTES or b"\n" not in raw:
            return {"ok": False, "error": "Requête invalide ou incomplète"}
        try:
            request = json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"ok": False, "error": "Requête illisible"}
        if not isinstance(request, dict):
            return {"ok": False, "error": "Requête invalide"}
        return self._broker.handle(request)


def send_request(request: dict[str, Any]) -> dict[str, Any]:
    """Envoie une requête à l'appli et attend la réponse (bloquant)."""
    QCoreApplication.instance() or QCoreApplication(sys.argv)
    socket = QLocalSocket()
    socket.connectToServer(server_name())
    if not socket.waitForConnected(CLIENT_CONNECT_MS):
        raise ServerUnavailable("L'application Vault n'est pas ouverte ou le coffre est verrouillé")

    socket.write((json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8"))
    socket.flush()

    data = bytearray()
    while b"\n" not in data:
        if not socket.waitForReadyRead(CLIENT_REPLY_MS):
            break
        data += bytes(socket.readAll())
    socket.disconnectFromServer()

    if b"\n" not in data:
        raise ServerUnavailable("Pas de réponse de l'application (délai dépassé ou fermée)")
    return json.loads(bytes(data).split(b"\n", 1)[0].decode("utf-8"))
