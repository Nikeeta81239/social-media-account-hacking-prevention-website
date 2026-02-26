# backend/routes/deviation_routes.py

import math
import datetime
from flask import Blueprint, jsonify, request
from database import get_db
from security.jwt_auth import token_required

deviation_bp = Blueprint("deviation", __name__)


def calculate_std_deviation(values):
    """Population std deviation: σ = sqrt(Σ(x-μ)²/N)"""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    return round(math.sqrt(variance), 2)


def get_risk_level(std_dev):
    """Risk level classification based on σ."""
    if std_dev <= 10:
        return "Low Risk", "🟢", "#10b981", "Login Allowed"
    elif std_dev <= 20:
        return "Medium Risk", "🟡", "#f59e0b", "OTP Verification"
    else:
        return "High Risk", "🔴", "#ef4444", "Account Temporarily Locked"


def get_variance_category(std_dev):
    if std_dev > 25:
        return "High Variance"
    elif std_dev > 10:
        return "Moderate Variance"
    return "Stable"


@deviation_bp.route("/deviation-data", methods=["GET"])
@token_required()
def deviation_data(current_user_id, role):
    db = get_db()
    cur = db.cursor(dictionary=True)

    # Check role
    cur.execute("SELECT role FROM users WHERE id=%s", (current_user_id,))
    user_row = cur.fetchone()
    role = user_row["role"] if user_row else "user"

    # Get regular users to analyze
    if role == "admin":
        cur.execute("SELECT id, email FROM users WHERE role='user'")
    else:
        cur.execute("SELECT id, email FROM users WHERE id=%s", (current_user_id,))
    
    users = cur.fetchall()

    user_deviations = []
    global_low = global_med = global_high = 0

    for user in users:
        user_id = user["id"]

        # Risk scores from attack_logs
        cur.execute("""
            SELECT risk_score, created_at FROM attack_logs
            WHERE user_id=%s ORDER BY created_at DESC
        """, (user_id,))
        attack_rows = cur.fetchall()
        attack_scores = [r["risk_score"] for r in attack_rows if r["risk_score"] is not None]

        # Risk scores from login_logs
        cur.execute("""
            SELECT risk, login_time, location, device, ip_address FROM login_logs
            WHERE user_id=%s ORDER BY id DESC
        """, (user_id,))
        login_rows = cur.fetchall()

        risk_map = {"low": 20, "medium": 50, "high": 80}
        login_scores = []
        login_times = []
        for r in login_rows:
            rv = (r.get("risk") or "").lower()
            if rv in risk_map:
                login_scores.append(risk_map[rv])
                lt = r.get("login_time")
                login_times.append(str(lt) if lt else "")

        all_scores = attack_scores + login_scores
        if not all_scores:
            continue

        mean_score = round(sum(all_scores) / len(all_scores), 2)
        std_dev = calculate_std_deviation(all_scores)
        max_score = max(all_scores)
        min_score = min(all_scores)
        risk_level, emoji, risk_color, action_taken = get_risk_level(std_dev)
        variance_category = get_variance_category(std_dev)

        # ---- Feature Breakdown ----
        total_logins = len(login_rows)
        location_changes = 0
        device_mismatches = 0
        odd_time_logins = 0

        locations = [r.get("location") for r in login_rows if r.get("location")]
        devices   = [r.get("device")   for r in login_rows if r.get("device")]

        if len(locations) > 1:
            unique_locs = len(set(locations))
            location_changes = unique_locs - 1

        if len(devices) > 1:
            base_device = devices[-1]  # oldest known device as baseline
            device_mismatches = sum(1 for d in devices if d != base_device)

        for r in login_rows:
            lt = r.get("login_time")
            if lt and hasattr(lt, 'hour'):
                h = lt.hour
            elif lt:
                try:
                    h = datetime.datetime.fromisoformat(str(lt)).hour
                except Exception:
                    h = 12
            else:
                h = 12
            if h < 6 or h > 22:
                odd_time_logins += 1

        # Feature risk contributions
        loc_risk  = min(location_changes * 20, 40)
        dev_risk  = min(device_mismatches * 10, 30)
        time_risk = min(odd_time_logins  * 20, 40)
        computed_total_risk = loc_risk + dev_risk + time_risk

        feature_breakdown = {
            "location_changes": location_changes,
            "location_risk": loc_risk,
            "device_mismatches": device_mismatches,
            "device_risk": dev_risk,
            "odd_time_logins": odd_time_logins,
            "time_risk": time_risk,
            "total_computed_risk": computed_total_risk
        }

        # ---- Current vs Historical Mean (latest score vs mean of rest) ----
        current_score = all_scores[0] if all_scores else mean_score
        historical_mean = round(sum(all_scores[1:]) / max(len(all_scores) - 1, 1), 2) if len(all_scores) > 1 else mean_score
        diff = round(current_score - historical_mean, 2)
        comparison_status = "Suspicious" if diff > 20 else ("Elevated" if diff > 0 else "Normal")

        # ---- Score timeline for chart (last 10) ----
        score_history = all_scores[:10][::-1]  # oldest first
        time_labels = (login_times[:len(login_scores)])[:10][::-1]

        # Global counts
        if "Low" in risk_level:
            global_low += 1
        elif "Medium" in risk_level:
            global_med += 1
        else:
            global_high += 1

        # Get latest XAI explanation for full narrative
        cur.execute("""
            SELECT top_reasons, risk_score FROM xai_explanations 
            WHERE user_id=%s ORDER BY created_at DESC LIMIT 1
        """, (user_id,))
        xai_row = cur.fetchone()
        
        latest_xai_reason = "Normal behavior detected (Deviation < 25%)"
        if xai_row:
            latest_xai_reason = f"Latest Risk: {xai_row['risk_score']}% — Reasons: {xai_row['top_reasons']}"

        user_deviations.append({
            "email": user["email"],
            "user_id": user_id,
            "total_events": len(all_scores),
            "mean_score": mean_score,
            "std_deviation": std_dev,
            "min_score": min_score,
            "max_score": max_score,
            "risk_level": risk_level,
            "risk_emoji": emoji,
            "risk_color": risk_color,
            "action_taken": action_taken,
            "variance_category": variance_category,
            "feature_breakdown": feature_breakdown,
            "current_score": current_score,
            "historical_mean": historical_mean,
            "score_diff": diff,
            "comparison_status": comparison_status,
            "score_history": score_history,
            "time_labels": time_labels,
            "scores": all_scores[-20:],
            "latest_xai_reason": latest_xai_reason
        })

    all_devs = [u["std_deviation"] for u in user_deviations]
    overall_mean_dev = round(sum(all_devs) / max(len(all_devs), 1), 2) if all_devs else 0
    overall_max_dev  = max(all_devs) if all_devs else 0

    cur.close()
    db.close()

    return jsonify({
        "users": user_deviations,
        "overall": {
            "total_users_analyzed": len(user_deviations),
            "mean_deviation": overall_mean_dev,
            "max_deviation": overall_max_dev,
            "std_deviation": round(calculate_std_deviation(all_devs), 2) if all_devs else 0
        },
        "global_risk": {
            "low": global_low,
            "medium": global_med,
            "high": global_high
        }
    })


# ================= DELETE USER DEVIATION DATA =================
@deviation_bp.route("/delete-deviation-user", methods=["POST"])
@token_required()
def delete_deviation_user(current_user_id, role):
    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"message": "user_id required"}), 400

    db = get_db()
    cur = db.cursor()
    # Delete from attack_logs and login_logs for this user
    cur.execute("DELETE FROM attack_logs WHERE user_id=%s", (user_id,))
    cur.execute("DELETE FROM login_logs WHERE user_id=%s", (user_id,))
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": "User deviation data cleared successfully"}), 200
