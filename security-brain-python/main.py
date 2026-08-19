from fastapi import FastAPI, HTTPException
import uvicorn
from pydantic import BaseModel, Field
import qrcode
import pyotp
import io
import base64

app = FastAPI(title="Aegis Security Brain")

# The schema matching our Java MfaClient request
class MfaSetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    secret: str = Field(min_length=16, max_length=128, pattern=r"^[A-Z2-7]+=*$")

# The schema for verification
class MfaVerifyRequest(BaseModel):
    secret: str = Field(min_length=16, max_length=128, pattern=r"^[A-Z2-7]+=*$")
    code: str = Field(pattern=r"^\d{6}$")

@app.post("/mfa/verify")
def verify_mfa(request: MfaVerifyRequest):
    try:
        totp = pyotp.TOTP(request.secret)
        # Verify the 6-digit code against the shared secret
        is_valid = totp.verify(request.code)

        if is_valid:
            return {"status": "success", "message": "Code verified"}
        raise HTTPException(status_code=400, detail="Invalid code")

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Unable to verify MFA code") from exc

@app.get("/health")
def health_check():
    return {"status": "active", "service": "security-brain"}

@app.post("/mfa/setup")
def generate_qr(request: MfaSetupRequest):
    try:
        # Generate TOTP provisioning URI
        # Format: otpauth://totp/Aegis:USERNAME?secret=SECRET&issuer=Aegis
        uri = f"otpauth://totp/Aegis:{request.username}?secret={request.secret}&issuer=Aegis"

        # Create QR Code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert image to Base64 string for the Java Heart to consume
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        img_str = base64.b64encode(buf.getvalue()).decode()

        return {
            "status": "success",
            "data": {
                "qr_code": img_str
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
