import asyncio
import sys

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from eimzo import EimzoApiError, list_eimzo_certificates, eimzo_pkcs7_timestamp


def win_selector_loop_factory() -> asyncio.AbstractEventLoop:
    """Selector loop on Windows; bundled in main.py so PyInstaller includes it (not loop_factory:...)."""
    return asyncio.SelectorEventLoop()


def _eimzo_http_exception(exc: EimzoApiError) -> HTTPException:
    """Map E-IMZO business errors to 4xx; leave unknown failures as 502."""
    p = exc.payload
    status = p.get("status")
    reason = str(p.get("reason") or "").lower()
    # -5000: PIN/password dialog cancelled (typical E-IMZO)
    if status == -5000 or "парол" in reason or "password" in reason:
        code = 400
    else:
        code = 502
    return HTTPException(
        status_code=code,
        detail={
            "success": False,
            "eimzo_status": p.get("status"),
            "reason": p.get("reason"),
        },
    )


app = FastAPI(
    title="E-IMZO Client",
    description="E-IMZO Client - Client for E-IMZO API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ORIGIN = "https://localhost"


@app.get("/list-certificates")
async def list_certificates():
    """List all E-IMZO certificates (same order as E-IMZO client)."""
    try:
        certs = await list_eimzo_certificates(ORIGIN)
        return {"certificates": certs}
    except EimzoApiError as e:
        raise _eimzo_http_exception(e)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


class SignRequest(BaseModel):
    data_b64: str
    cert_index: int = 0


@app.post("/sign")
async def sign(request: SignRequest):
    """Sign data with the certificate at the given index. Returns pkcs7_64 and signature_hex for Didox login."""
    try:
        pkcs7_64, signature_hex = await eimzo_pkcs7_timestamp(
            request.data_b64, ORIGIN, request.cert_index
        )
        return {"pkcs7_64": pkcs7_64, "signature_hex": signature_hex}
    except EimzoApiError as e:
        raise _eimzo_http_exception(e)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    # Uvicorn forces ProactorEventLoop on Windows; Selector avoids E-IMZO RST noise.
    # __main__:... works for python main.py and PyInstaller (no separate loop_factory module).
    loop_kw = {}
    if sys.platform == "win32":
        loop_kw["loop"] = "__main__:win_selector_loop_factory"

    uvicorn.run(app, host="0.0.0.0", port=8444, **loop_kw)