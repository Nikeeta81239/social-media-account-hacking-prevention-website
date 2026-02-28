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


def get_risk_level(avg_score, is_blocked=False):
    """Sync with XAI logic: Low < 31, Med 31-69, High >= 70."""
    if is_blocked:
        return "Account Blocked", "🚫", "#ef4444", "Access Restricted (30s Lock)"
    
    if avg_score < 31:
        return "Low Risk", "🟢", "#10b981", "Login Allowed"
    elif avg_score < 70:
        return "Medium Risk", "🟡", "#f59e0b", "OTP Verification Required"
    else:
        return "High Risk", "🔴", "#ef4444", "Advanced Identity Check"


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

        # Risk mapping for logs
        risk_map = {"low": 20, "medium": 50, "high": 85}
        login_scores = []
        login_times = []
        for r in login_rows:
            rv = (r.get("risk") or "").lower()
            if rv in risk_map:
                login_scores.append(risk_map[rv])
                lt = r.get("login_time")
                login_times.append(str(lt) if lt else "")

        # Check if user is currently blocked
        cur.execute("SELECT blocked_time FROM blocked_users WHERE user_id=%s ORDER BY blocked_time DESC LIMIT 1", (user_id,))
        block_row = cur.fetchone()
        is_blocked = False
        if block_row:
            diff = (datetime.datetime.utcnow() - block_row['blocked_time']).total_seconds()
            if diff < 30:
                is_blocked = True

        all_scores = attack_scores + login_scores
        if not all_scores:
            # Fallback for users with no logs yet
            all_scores = [0]

        mean_score = round(sum(all_scores) / len(all_scores), 2)
        std_dev = calculate_std_deviation(all_scores)
        max_score = max(all_scores)
        min_score = min(all_scores)
        
        # Use mean_score for level classification to match XAI results
        risk_level, emoji, risk_color, action_taken = get_risk_level(mean_score, is_blocked)
        variance_category = get_variance_category(std_dev)

        # ---- Feature Breakdown ----
        total_logins = len(login_rows)
        location_changes = 0
        device_mismatches = 0
        odd_time_logins = 0
        night_logins = 0

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
            
            # Identify night logins (11 PM - 6 AM)
            if h < 6 or h >= 23:
                night_logins += 1
            
            # Original odd time logic (extended for safety)
            if h < 7 or h > 22:
                odd_time_logins += 1

        # Feature risk contributions
        loc_risk  = min(location_changes * 20, 40)
        dev_risk  = min(device_mismatches * 10, 30)
        # Night-based focus for time risk
        time_risk = min(night_logins * 25, 50) 
        computed_total_risk = loc_risk + dev_risk + time_risk

        feature_breakdown = {
            "location_changes": location_changes,
            "location_risk": loc_risk,
            "device_mismatches": device_mismatches,
            "device_risk": dev_risk,
            "odd_time_logins": odd_time_logins,
            "night_logins": night_logins,
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

        # Get latest XAI explanation for full narrative and plain-language reason
        cur.execute("""
            SELECT top_reasons, risk_score, decision, trust_score, created_at
            FROM xai_explanations 
            WHERE user_id=%s ORDER BY created_at DESC LIMIT 1
        """, (user_id,))
        xai_row = cur.fetchone()

        latest_xai_reason = "No suspicious activity detected. Login behavior is within normal parameters."
        latest_xai_admin_detail = "Normal behavior detected (Deviation < 25%)"
        xai_login_time = None
        xai_risk_score = None
        xai_decision = "Low Risk"

        if xai_row:
            xai_risk_score = xai_row.get("risk_score", 0)
            xai_decision = xai_row.get("decision", "Low Risk")
            raw_ts = xai_row.get("created_at")
            xai_login_time = str(raw_ts) if raw_ts else None

            try:
                import json as _json
                top_data = _json.loads(xai_row["top_reasons"] or "{}")

                # ── Plain-language prompt for USER view ──
                lime_prompt = top_data.get("lime_user_prompt") or top_data.get("reason") or ""
                if lime_prompt:
                    latest_xai_reason = lime_prompt
                else:
                    # Fallback: generate from risk score
                    if xai_risk_score and xai_risk_score >= 70:
                        latest_xai_reason = (
                            "High-risk login behavior detected. Your location, device, or login frequency "
                            "significantly deviated from your normal pattern."
                        )
                    elif xai_risk_score and xai_risk_score >= 31:
                        latest_xai_reason = (
                            "Moderate behavioral deviation detected. Identity verification was requested "
                            "as a precautionary security measure."
                        )
                    else:
                        latest_xai_reason = (
                            "Your login activity matches your usual device, location, and usage pattern. "
                            "No unusual behavior was detected. Your account access is safe."
                        )

                # ── Admin-level technical detail ──
                dyn = top_data.get("dynamic_analysis", [])
                login_time_utc = top_data.get("login_time_utc", "")
                failed_ever = top_data.get("failed_ever", 0)
                freq_24h = top_data.get("freq_24h", 0)

                latest_xai_admin_detail = (
                    f"Risk: {xai_risk_score}% | UTC: {login_time_utc} | "
                    f"Failed (All Time): {failed_ever} | 24h Logins: {freq_24h} | "
                    + " | ".join(dyn[:3])
                )
            except Exception as _e:
                latest_xai_reason = f"Risk Score: {xai_risk_score}% — {xai_decision}"
                latest_xai_admin_detail = latest_xai_reason

        user_deviations.append({
            "email":                    user["email"],
            "user_id":                  user_id,
            "total_events":             len(all_scores),
            "mean_score":               mean_score,
            "std_deviation":            std_dev,
            "min_score":                min_score,
            "max_score":                max_score,
            "risk_level":               risk_level,
            "risk_emoji":               emoji,
            "risk_color":               risk_color,
            "action_taken":             action_taken,
            "variance_category":        variance_category,
            "feature_breakdown":        feature_breakdown,
            "current_score":            current_score,
            "historical_mean":          historical_mean,
            "score_diff":               diff,
            "comparison_status":        comparison_status,
            "score_history":            score_history,
            "time_labels":              time_labels,
            "scores":                   all_scores[-20:],
            # Plain-language AI explanation (user-friendly)
            "latest_xai_reason":        latest_xai_reason,
            # Technical detail for admin panel
            "latest_xai_admin_detail":  latest_xai_admin_detail,
            # XAI metadata
            "xai_login_time":           xai_login_time,
            "xai_risk_score":           xai_risk_score,
            "xai_decision":             xai_decision,
            "is_blocked":               is_blocked
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
