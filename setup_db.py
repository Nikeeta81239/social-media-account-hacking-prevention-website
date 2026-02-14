import mysql.connector

conn = mysql.connector.connect(
    host='localhost',
    port=3306,
    user='root',
    password='dbms123456789@#'
)
cur = conn.cursor()

cur.execute('CREATE DATABASE IF NOT EXISTS ai_social_security')
cur.execute('USE ai_social_security')

cur.execute("""CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)""")

cur.execute("""CREATE TABLE IF NOT EXISTS blocked_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    reason VARCHAR(100),
    blocked_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)""")

cur.execute("""CREATE TABLE IF NOT EXISTS login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(50),
    location VARCHAR(50),
    device VARCHAR(50),
    status VARCHAR(20),
    risk VARCHAR(10),
    FOREIGN KEY (user_id) REFERENCES users(id)
)""")

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

# Insert sample data
try:
    cur.execute(
        "INSERT INTO users (email, password, role) VALUES "
        "('admin123@gmail.com', 'admin123@#', 'admin'), "
        "('user123@gmail.com', 'user123@#', 'user')"
    )
    print("Users inserted.")
except Exception as e:
    print(f"Users already exist or error: {e}")

try:
    cur.execute(
        "INSERT INTO login_logs (user_id, ip_address, location, device, status, risk) VALUES "
        "(1, '127.0.0.1', 'Local', 'Desktop', 'success', 'low'), "
        "(2, '203.0.113.45', 'Unknown', 'Mobile', 'Suspicious', 'high'), "
        "(2, '192.168.1.1', 'Local', 'Desktop', 'success', 'low'), "
        "(2, '41.0.0.1', 'Unknown', 'Unknown', 'Suspicious', 'high')"
    )
    print("Login logs inserted.")
except Exception as e:
    print(f"Login logs error: {e}")

try:
    cur.execute(
        "INSERT INTO attack_logs (user_id, ip_address, risk_score, status) VALUES "
        "(2, '203.0.113.45', 87, 'SUSPICIOUS'), "
        "(2, '41.0.0.1', 65, 'SUSPICIOUS')"
    )
    print("Attack logs inserted.")
except Exception as e:
    print(f"Attack logs error: {e}")

try:
    cur.execute(
        "INSERT INTO xai_explanations (user_id, event_type, risk_score, decision, top_reasons, what_if, trust_score) VALUES "
        "(2, 'LOGIN_ATTEMPT', 87, 'Fake / Bot', "
        "'High login frequency, Low engagement ratio, New account age, Repetitive behavior', "
        "'If login frequency reduced and engagement improved, risk would drop to 35%%', 42)"
    )
    print("XAI data inserted.")
except Exception as e:
    print(f"XAI data error: {e}")

conn.commit()
cur.close()
conn.close()
print("\nDatabase setup complete! All tables and sample data created.")
