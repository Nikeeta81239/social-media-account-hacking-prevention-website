# backend/routes/deviation_routes.py

import math
from flask import Blueprint, jsonify
from database import get_db

deviation_bp = Blueprint("deviation", __name__)


def calculate_std_deviation(values):
    """Calculate standard deviation of a list of numbers."""
    if len(values) < 2:
        return 0.0
    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return round(math.sqrt(variance), 2)


@deviation_bp.route("/deviation-data", methods=["GET"])
def deviation_data():
    """
    Calculate standard deviation of login risk scores across users.
    Returns per-user deviation analysis and overall statistics.
    """
    db = get_db()
    cur = db.cursor(dictionary=True)

    # Get all users
    cur.execute("SELECT id, email FROM users WHERE role='user'")
    users = cur.fetchall()

    user_deviations = []

    for user in users:
        user_id = user["id"]

        # Get risk scores from attack logs
        cur.execute("""
            SELECT risk_score FROM attack_logs
            WHERE user_id=%s
            ORDER BY created_at DESC
        """, (user_id,))
        attack_rows = cur.fetchall()
        attack_scores = [r["risk_score"] for r in attack_rows if r["risk_score"] is not None]

        # Get login log risk levels and convert to numeric
        cur.execute("""
            SELECT risk FROM login_logs
            WHERE user_id=%s
            ORDER BY id DESC
        """, (user_id,))
        login_rows = cur.fetchall()

        risk_map = {"low": 20, "medium": 50, "high": 80}
        login_scores = []
        for r in login_rows:
            risk_val = r.get("risk")
            if risk_val and risk_val.lower() in risk_map:
                login_scores.append(risk_map[risk_val.lower()])

        # Combine all risk scores
        all_scores = attack_scores + login_scores

        if len(all_scores) == 0:
            continue

        mean_score = round(sum(all_scores) / len(all_scores), 2)
        std_dev = calculate_std_deviation(all_scores)
        max_score = max(all_scores)
        min_score = min(all_scores)

        # Determine risk category based on deviation
        if std_dev > 25:
            risk_category = "High Variance"
            risk_color = "#ef4444"
        elif std_dev > 10:
            risk_category = "Moderate Variance"
            risk_color = "#f59e0b"
        else:
            risk_category = "Stable"
            risk_color = "#10b981"

        user_deviations.append({
            "email": user["email"],
            "total_events": len(all_scores),
            "mean_score": mean_score,
            "std_deviation": std_dev,
            "min_score": min_score,
            "max_score": max_score,
            "risk_category": risk_category,
            "risk_color": risk_color,
            "scores": all_scores[-20:]  # last 20 scores for chart
        })

    # Overall statistics
    all_devs = [u["std_deviation"] for u in user_deviations]
    overall_mean_dev = round(sum(all_devs) / max(len(all_devs), 1), 2) if all_devs else 0
    overall_max_dev = max(all_devs) if all_devs else 0

    cur.close()
    db.close()

    return jsonify({
        "users": user_deviations,
        "overall": {
            "total_users_analyzed": len(user_deviations),
            "mean_deviation": overall_mean_dev,
            "max_deviation": overall_max_dev
        }
    })
