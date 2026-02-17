from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import qrcode
import io
import base64

app = FastAPI(title="Aegis Security Brain")

# The schema matching our Java MfaClient request
class MfaSetupRequest(BaseModel):
    username: str
    secret: str

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