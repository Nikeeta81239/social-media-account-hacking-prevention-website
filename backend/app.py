# backend/app.py

from flask import Flask, render_template
from routes.auth_routes import auth_bp
from routes.admin_routes import admin_bp
from routes.monitoring_routes import monitoring_bp

app = Flask(
    __name__,
    template_folder="../frontend",
    static_folder="../frontend"
)

app.secret_key = "super_secret"

# Register APIs
app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(admin_bp, url_prefix="/api")
app.register_blueprint(monitoring_bp, url_prefix="/api")

# ---------- FRONTEND ROUTES ----------

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/otp-verification")
def otp_page():
    return render_template("otp-verification.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/activity-logs")
def activity_logs():
    return render_template("activity-logs.html")

@app.route("/admin-dashboard")
def admin_dashboard():
    return render_template("admin-dashboard.html")

@app.route("/blocked-account")
def blocked_accounts():
    return render_template("blocked-account.html")

@app.route("/xai")
def xai():
    return render_template("xai-explanation.html")

# -----------------------------------

if __name__ == "__main__":
    app.run(debug=True)
