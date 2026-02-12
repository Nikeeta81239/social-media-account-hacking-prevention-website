from flask import request

def get_device():
    user_agent = request.headers.get("User-Agent", "").lower()

    if "mobile" in user_agent:
        return "Mobile"
    elif "tablet" in user_agent:
        return "Tablet"
    elif "windows" in user_agent or "mac" in user_agent or "linux" in user_agent:
        return "Desktop"
    else:
        return "Unknown"
