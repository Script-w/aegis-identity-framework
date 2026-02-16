from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from app.services.mfa_service import MfaService

# Initialize the FastAPI app
app = FastAPI(
    title="Aegis Security Brain",
    description="Intelligent MFA and Security Logic Layer",
    version="1.0.0"
)

# Pydantic model for incoming requests (ensures data integrity)
class MfaSetupRequest(BaseModel):
    username: str
    secret: str

# Dependency Injection for our service
def get_mfa_service():
    return MfaService(issuer_name="AegisFramework")

@app.get("/health")
async def health_check():
    """Service health check for CI/CD and Orchestration."""
    return {"status": "active", "service": "security-brain"}

@app.post("/mfa/setup")
async def setup_mfa(
    request: MfaSetupRequest, 
    service: MfaService = Depends(get_mfa_service)
):
    """
    Receives a username and secret (from Java Core),
    returns a Base64 QR code for the frontend.
    """
    try:
        qr_code_base64 = service.generate_qr_code(
            username=request.username, 
            secret_base64=request.secret
        )
        
        return {
            "status": "success",
            "data": {
                "username": request.username,
                "qr_code": qr_code_base64,
                "content_type": "image/png",
                "encoding": "base64"
            }
        }
    except Exception as e:
        # Log the error and return a 500
        print(f"MFA Setup Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate MFA QR code")

# Entry point for local execution on your Cubot Tab 60
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
