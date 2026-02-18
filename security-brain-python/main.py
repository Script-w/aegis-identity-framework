from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import qrcode
import pyotp
import io
import base64

app = FastAPI(title="Aegis Security Brain")

# The schema matching our Java MfaClient request
class MfaSetupRequest(BaseModel):
    username: str
    secret: str

# The schema for verification
class MfaVerifyRequest(BaseModel):
    secret: str
    code: str

@app.post("/mfa/verify")
def verify_mfa(request: MfaVerifyRequest):
    try:
        totp = pyotp.TOTP(request.secret)
        # Verify the 6-digit code against the shared secret
        is_valid = totp.verify(request.code)
        
        if is_valid:
            return {"status": "success", "message": "Code verified"}
        else:
            return {"status": "failure", "message": "Invalid code"}, 400
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
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