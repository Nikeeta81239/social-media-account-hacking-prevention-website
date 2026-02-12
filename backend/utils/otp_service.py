# backend/utils/otp_service.py

import random
import time

# In-memory OTP store
otp_store = {}

def generate_otp(user_id):
    otp = f"{random.randint(0, 9999):04d}"

    otp_store[user_id] = {
        "otp": otp,
        "expires_at": time.time() + 120  # 2 minutes
    }

    return otp


def verify_otp(user_id, entered_otp):
    data = otp_store.get(user_id)

    if not data:
        return False, "OTP not found"

    if time.time() > data["expires_at"]:
        otp_store.pop(user_id)
        return False, "OTP expired"

    if data["otp"] != entered_otp:
        return False, "Invalid OTP"

    otp_store.pop(user_id)
    return True, "OTP verified successfully"
