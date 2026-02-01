from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from eimzo import list_eimzo_certificates, eimzo_pkcs7_timestamp

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
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8444)
