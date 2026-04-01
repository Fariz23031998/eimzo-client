import asyncio
import json
import ssl

import aiohttp
from aiohttp import WSMsgType

EIMZO_WS_URL = "wss://127.0.0.1:64443/service/cryptapi"


class EimzoApiError(Exception):
    """Raised when E-IMZO returns JSON with success: false (user or key error)."""

    def __init__(self, payload: dict):
        self.payload = payload
        reason = payload.get("reason")
        if reason is not None:
            super().__init__(str(reason))
        else:
            super().__init__(str(payload))

# E-IMZO may block on PIN / hardware; avoid hanging the HTTP client forever.
_RECV_TIMEOUT_S = 300.0
# PKCS#7 in JSON can exceed aiohttp's default 4 MiB.
_MAX_WS_MSG = 32 * 1024 * 1024

# Public domain keys shipped with E-IMZO apidoc (same as CAPIWS.apikey in apidoc.html).
_APIKEY_ARGUMENTS = [
    "localhost",
    "96D0C1491615C82B9A54D9989779DF825B690748224C2B04F500F370D51827CE2644D8D4A82C18184D73AB8530BB8ED537269603F61DB0D03D2104ABF789970B",
    "127.0.0.1",
    "A7BCFA5D490B351BE0754130DF03A068F855DB4333D43921125B9CF2670EF6A40370C646B90401955E1F7BC9CDBF59CE0B2C5467D820BE189C845D0B79CFC96F",
    "null",
    "E0A205EC4E7B78BBB56AFF83A733A1BB9FD39D562E67978CC5E7D73B0951DB1954595A20672A63332535E13CC6EC1E1FC8857BB09E0855D7E76E411B6FA16E9D",
]

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE
ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

_apikey_lock = asyncio.Lock()
_apikey_registered = False


async def _ensure_apikey(origin: str) -> None:
    """E-IMZO v6+ expects the same apikey handshake as the bundled apidoc page."""
    global _apikey_registered
    async with _apikey_lock:
        if _apikey_registered:
            return
        resp = await _eimzo_exchange(
            {"name": "apikey", "arguments": _APIKEY_ARGUMENTS},
            origin,
        )
        if resp.get("success") is False:
            raise EimzoApiError(resp)
        _apikey_registered = True


async def _ws_recv_json(ws: aiohttp.ClientWebSocketResponse) -> dict:
    while True:
        msg = await asyncio.wait_for(ws.receive(), timeout=_RECV_TIMEOUT_S)
        if msg.type == WSMsgType.TEXT:
            return json.loads(msg.data)
        if msg.type == WSMsgType.BINARY:
            return json.loads(msg.data.decode("utf-8"))
        if msg.type == WSMsgType.CLOSE:
            data = msg.data
            if isinstance(data, tuple) and len(data) >= 2:
                code, reason = data[0], data[1]
                raise RuntimeError(
                    f"E-IMZO closed the socket without a JSON reply "
                    f"(code={code}, reason={reason!r})"
                )
            raise RuntimeError("E-IMZO closed the socket without a JSON reply")
        if msg.type == WSMsgType.ERROR:
            exc = ws.exception()
            raise RuntimeError(f"WebSocket error: {exc!r}") from exc
        if msg.type == WSMsgType.CLOSED:
            raise RuntimeError("E-IMZO WebSocket closed before a reply")


async def _eimzo_exchange(payload: dict, origin: str) -> dict:
    """
    One TLS WebSocket, one JSON command, one JSON reply — same pattern as
    CAPIWS.callFunction. Avoids python-websockets close-handshake issues when
    E-IMZO sends 1000 "Done" and resets TCP (common on Windows Proactor).
    """
    timeout = aiohttp.ClientTimeout(sock_connect=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.ws_connect(
            EIMZO_WS_URL,
            origin=origin,
            ssl=ssl_context,
            server_hostname="127.0.0.1",
            autoping=True,
            max_msg_size=_MAX_WS_MSG,
            compress=0,
        ) as ws:
            await ws.send_str(json.dumps(payload, ensure_ascii=False))
            return await _ws_recv_json(ws)


async def list_eimzo_certificates(origin: str):
    """
    List all available E-IMZO certificates.
    Returns a list of certificate objects.
    """
    await _ensure_apikey(origin)
    resp = await _eimzo_exchange(
        {"plugin": "pfx", "name": "list_all_certificates"},
        origin,
    )
    certs = resp.get("certificates", [])
    if not certs:
        raise RuntimeError("No E-IMZO certificates found")
    return certs


async def eimzo_pkcs7_timestamp(data_b64: str, origin: str, cert_index: int = 0):
    """
    Sign data using E-IMZO and get timestamp.

    Each step uses its own WebSocket (E-IMZO closes after each reply). The
    service keeps keyId in-process so load_key and create_pkcs7 can run on
    different connections after apikey registration.

    Args:
        data_b64: Base64 encoded data to sign
        origin: Origin header for WebSocket connection
        cert_index: Index of certificate to use (default: 0 for first certificate)

    Returns:
        Tuple of (pkcs7_64, signature_hex)
    """
    certs = await list_eimzo_certificates(origin)
    if cert_index < 0 or cert_index >= len(certs):
        raise RuntimeError(
            f"Invalid certificate index: {cert_index}. "
            f"Available: 0-{len(certs) - 1}"
        )
    cert = certs[cert_index]

    resp = await _eimzo_exchange(
        {
            "plugin": "pfx",
            "name": "load_key",
            "arguments": [
                cert["disk"],
                cert["path"],
                cert["name"],
                cert["alias"],
            ],
        },
        origin,
    )
    if resp.get("success") is False:
        raise EimzoApiError(resp)
    key_id = resp.get("keyId")
    if not key_id:
        raise EimzoApiError(resp)

    sign_resp = await _eimzo_exchange(
        {
            "plugin": "pkcs7",
            "name": "create_pkcs7",
            "arguments": [data_b64, key_id, "no"],
        },
        origin,
    )

    if not sign_resp.get("success"):
        raise EimzoApiError(sign_resp)

    return (sign_resp["pkcs7_64"], sign_resp["signature_hex"])
