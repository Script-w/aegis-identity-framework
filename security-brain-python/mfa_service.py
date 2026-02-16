import pyotp
import qrcode
import io
import base64

class MfaService:
    def __init__(self, issuer_name: str = "AegisFramework"):
        self.issuer_name = issuer_name

    def generate_qr_code(self, username: str, secret_base64: str):
        """
        Generates a base64 encoded QR code image for a given secret.
        The secret must be the same one stored in the Java database.
        """
        # Create the provisioning URI (matching Java's TotpManager logic)
        uri = pyotp.totp.TOTP(secret_base64).provisioning_uri(
            name=username, 
            issuer_name=self.issuer_name
        )

        # Generate the QR Code image
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        
        # Encode to base64 so it can be sent via JSON to the frontend
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def verify_backup_code(self, code: str, secret_base64: str):
        """Python-side verification (useful for internal health checks)"""
        totp = pyotp.TOTP(secret_base64)
        return totp.verify(code)
      
