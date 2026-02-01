import ssl
import json
import websockets

EIMZO_WS_URL = "wss://127.0.0.1:64443/service/cryptapi"

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE
ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1


async def list_eimzo_certificates(origin: str):
    """
    List all available E-IMZO certificates.
    Returns a list of certificate objects.
    """
    async with websockets.connect(
        EIMZO_WS_URL,
        ssl=ssl_context,
        server_hostname="127.0.0.1",  # IMPORTANT
        additional_headers={
            "Origin": origin
        }
    ) as ws:
        # List certificates
        await ws.send(json.dumps({
            "plugin": "pfx",
            "name": "list_all_certificates"
        }))
        resp = json.loads(await ws.recv())
        certs = resp.get("certificates", [])
        if not certs:
            raise RuntimeError("No E-IMZO certificates found")
        return certs


async def eimzo_pkcs7_timestamp(data_b64: str, origin: str, cert_index: int = 0):
    """
    Sign data using E-IMZO and get timestamp.
    
    Args:
        data_b64: Base64 encoded data to sign
        origin: Origin header for WebSocket connection
        cert_index: Index of certificate to use (default: 0 for first certificate)
    
    Returns:
        Tuple of (pkcs7_64, signature_hex)
    """
    async with websockets.connect(
        EIMZO_WS_URL,
        ssl=ssl_context,
        server_hostname="127.0.0.1",  # IMPORTANT
        additional_headers={
            "Origin": origin
        }
    ) as ws:

        # 1. List certificates
        await ws.send(json.dumps({
            "plugin": "pfx",
            "name": "list_all_certificates"
        }))
        resp = json.loads(await ws.recv())
        certs = resp.get("certificates", [])
        if not certs:
            raise RuntimeError("No E-IMZO certificates found")
        
        if cert_index < 0 or cert_index >= len(certs):
            raise RuntimeError(f"Invalid certificate index: {cert_index}. Available: 0-{len(certs)-1}")
        
        cert = certs[cert_index]

        # 2. Load key
        await ws.send(json.dumps({
            "plugin": "pfx",
            "name": "load_key",
            "arguments": [
                cert["disk"],
                cert["path"],
                cert["name"],
                cert["alias"]
            ]
        }))
        resp = json.loads(await ws.recv())
        key_id = resp.get("keyId")
        if not key_id:
            raise RuntimeError("Failed to load key")

        # 3. Create PKCS7
        await ws.send(json.dumps({
            "plugin": "pkcs7",
            "name": "create_pkcs7",
            "arguments": [data_b64, key_id, "no"]
        }))
        sign_resp = json.loads(await ws.recv())

        if not sign_resp.get("success"):
            raise RuntimeError(sign_resp)

        return (
            sign_resp["pkcs7_64"],
            sign_resp["signature_hex"]
        )