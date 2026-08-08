import os
from twilio.rest import Client # type: ignore
from dotenv import load_dotenv

load_dotenv()

# 🔐 Your Twilio credentials
account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
service_sid = os.environ.get("TWILIO_SERVICE_SID")

client = Client(account_sid, auth_token)

# 📩 Send OTP
def send_otp(phone):
    verification = client.verify.v2.services(service_sid).verifications.create(
        to=phone,
        channel="sms"
    )
    return verification.status

# ✅ Verify OTP
def verify_otp(phone, otp):
    verification_check = client.verify.v2.services(service_sid).verification_checks.create(
        to=phone,
        code=otp
    )
    return verification_check.status == "approved"