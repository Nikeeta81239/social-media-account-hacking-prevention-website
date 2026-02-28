# backend/app.py

from flask import Flask, render_template
from flask_cors import CORS
from backend.database import get_db
from routes.auth_routes import auth_bp
from routes.admin_routes import admin_bp
from routes.monitoring_routes import monitoring_bp
from routes.dashboard_routes import dashboard_bp
from routes.register_routes import register_bp
from routes.deviation_routes import deviation_bp
from routes.fake_profile_routes import fake_profile_bp

app = Flask(
    __name__,
    template_folder="../frontend",
    static_folder="../frontend"
)

app.secret_key = "super_secret"
CORS(app)

# Register APIs
app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(admin_bp, url_prefix="/api")
app.register_blueprint(monitoring_bp, url_prefix="/api")
app.register_blueprint(dashboard_bp, url_prefix="/api")
app.register_blueprint(register_bp, url_prefix="/api")
app.register_blueprint(deviation_bp, url_prefix="/api")
app.register_blueprint(fake_profile_bp, url_prefix="/api")


# ========== AUTO-CREATE TABLES ON STARTUP ==========
def init_database():
    try:
        db = get_db()
        cur = db.cursor()

        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
            failed_attempts INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        cur.execute("""CREATE TABLE IF NOT EXISTS blocked_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            reason VARCHAR(255),
            blocked_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

        cur.execute("""CREATE TABLE IF NOT EXISTS login_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(50),
            location VARCHAR(150),
            device VARCHAR(255),
            status VARCHAR(30),
            risk VARCHAR(10),
            behavior_reason TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

        # Widen columns on existing databases (safe to run every time)
        try:
            cur.execute("ALTER TABLE login_logs MODIFY COLUMN device VARCHAR(255)")
            cur.execute("ALTER TABLE login_logs MODIFY COLUMN location VARCHAR(150)")
            cur.execute("ALTER TABLE login_logs MODIFY COLUMN status VARCHAR(30)")
            cur.execute("ALTER TABLE blocked_users MODIFY COLUMN reason VARCHAR(255)")
            
            # Check if behavior_reason exists before adding it (safer for older MySQL)
            cur.execute("""
                SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'login_logs' 
                AND COLUMN_NAME = 'behavior_reason'
                AND TABLE_SCHEMA = (SELECT DATABASE())
            """)
            if cur.fetchone()[0] == 0:
                cur.execute("ALTER TABLE login_logs ADD COLUMN behavior_reason TEXT")
                print("[DATABASE] Added 'behavior_reason' column to login_logs.")
                
        except Exception as e:
            print(f"[DATABASE ERROR] Could not update schema: {str(e)}")
            pass


        cur.execute("""CREATE TABLE IF NOT EXISTS attack_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            ip_address VARCHAR(50),
            risk_score INT,
            status VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

        cur.execute("""CREATE TABLE IF NOT EXISTS xai_explanations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            event_type VARCHAR(50),
            risk_score INT,
            decision VARCHAR(50),
            top_reasons TEXT,
            what_if TEXT,
            trust_score INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

        cur.execute("""CREATE TABLE IF NOT EXISTS fake_profile_analysis (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            followers_count INT,
            following_count INT,
            post_count INT,
            account_age_days INT,
            trust_score INT,
            is_fake BOOLEAN,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

        db.commit()
        cur.close()
        db.close()
        print("[OK] Database tables ready!")
    except Exception as e:
        print(f"[ERROR] Database init error: {e}")


# ---------- FRONTEND ROUTES ----------

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

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

@app.route("/admin-blocked")
def admin_blocked_page():
    return render_template("admin-blocked-users.html")

@app.route("/blocked-account")
def blocked_accounts():
    return render_template("blocked-account.html")

@app.route("/xai")
def xai():
    return render_template("xai-explanation.html")

@app.route("/deviation")
def deviation():
    return render_template("deviation.html")

@app.route("/security-recovery")
def security_recovery():
    return render_template("security-recovery.html")

# -----------------------------------

if __name__ == "__main__":
    init_database()
    # Using port 8080 as port 5000 is sometimes restricted by browsers or system services
    app.run(host='0.0.0.0', port=8080, debug=True)
