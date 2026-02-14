# backend/utils/otp_service.py

import random
import time
from config import Config

# 🔐 In-memory OTP storage
otp_store = {}

def generate_otp(user_id):
    # Always store user_id as string to avoid type mismatch
    uid = str(user_id)
    otp = f"{random.randint(0, 9999):04d}"

    otp_store[uid] = {
        "otp": otp,
        "expires_at": time.time() + Config.OTP_EXPIRY_SECONDS
    }

    print(f"[DEBUG] Generated OTP for User {uid}: {otp}")
    return otp


def verify_otp(user_id, entered_otp):
    uid = str(user_id)
    data = otp_store.get(uid)

    if not data:
        print(f"[DEBUG] OTP verification failed: User {uid} not in store. Keys: {list(otp_store.keys())}")
        return False, "OTP session not found. Please login again."

    if time.time() > data["expires_at"]:
        otp_store.pop(uid)
        return False, "OTP expired"

    if data["otp"] != entered_otp:
        return False, "Invalid OTP"

    otp_store.pop(uid)
    return True, "OTP verified successfully"
