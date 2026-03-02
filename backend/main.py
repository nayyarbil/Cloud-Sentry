import os
import time
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt

from pydantic import BaseModel
from engine.attack_logic import generate_attack_vectors

# Import the individual intelligence cells directly
from engine.dns_cell import run_dns_recon
from engine.network_cell import run_network_recon
from engine.web_cell import run_web_recon

load_dotenv()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Token")
    try:
        token = authorization.split(" ")[1]
        return jwt.get_unverified_claims(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Token")

# --- TACTICAL ENDPOINTS ---

@app.post("/scan/dns")
async def scan_dns(target: str, user=Depends(verify_token)):
    print(f"--- RUNNING DNS RECON: {target} ---")
    return {"results": run_dns_recon(target)}

@app.post("/scan/network")
async def scan_network(target: str, user=Depends(verify_token)):
    print(f"--- RUNNING NETWORK RECON: {target} ---")
    return {"results": run_network_recon(target)}

@app.post("/scan/web")
async def scan_web(target: str, user=Depends(verify_token)):
    print(f"--- RUNNING WEB RECON: {target} ---")
    return {"results": run_web_recon(target)}

# Model to accept the intel from the frontend
class IntelPayload(BaseModel):
    dns: dict | None = None
    network: dict | None = None
    web: dict | None = None

@app.post("/scan/analyze")
async def scan_analyze(payload: IntelPayload, user=Depends(verify_token)):
    print(f"--- RUNNING THREAT ANALYSIS ---")
    # Feed the frontend data into the tactician engine
    vectors = generate_attack_vectors(payload.network or {}, payload.web or {}, payload.dns or {})
    return {"results": vectors}