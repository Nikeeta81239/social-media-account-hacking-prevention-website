#login_routes.py
from flask import Blueprint, request, jsonify
from models.login_log_model import log_login
from utils.device_detection import get_device
from utils.location_detection import get_location
from security.ip_reputation import check_ip

login_bp = Blueprint("login", __name__)

@login_bp.route("/api/log-login", methods=["POST"])
def log_user_login():
    data = request.json
    ip = data["ip"]
    user_id = data["user_id"]

    device = get_device()
    location = get_location(ip)

    status = "Suspicious" if check_ip(ip) else "Success"
    log_login(user_id, ip, str(location), device, status)

    return jsonify({"logged": True})
