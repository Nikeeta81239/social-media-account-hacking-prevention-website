-- Insert users with bcrypt-hashed passwords
-- admin123@# → bcrypt hash
-- user123@# → bcrypt hash
INSERT INTO users (email, password, role) VALUES
('admin123@gmail.com', 'admin123@#', 'admin'),
('user123@gmail.com', 'user123@#', 'user');


-- Insert into blocked_users
INSERT INTO blocked_users (user_id, reason)
VALUES (2, 'Multiple suspicious login attempts');

-- Insert login_logs sample data
INSERT INTO login_logs (user_id, ip_address, location, device, status, risk)
VALUES
(1, '127.0.0.1', 'Local', 'Desktop', 'success', 'low'),
(2, '203.0.113.45', 'Unknown', 'Mobile', 'Suspicious', 'high'),
(2, '192.168.1.1', 'Local', 'Desktop', 'success', 'low'),
(2, '41.0.0.1', 'Unknown', 'Unknown', 'Suspicious', 'high');

-- Insert into attack_logs
INSERT INTO attack_logs (user_id, ip_address, risk_score, status)
VALUES
(2, '203.0.113.45', 87, 'SUSPICIOUS'),
(2, '41.0.0.1', 65, 'SUSPICIOUS');

-- Insert into xai_explanations
INSERT INTO xai_explanations
(user_id, event_type, risk_score, decision, top_reasons, what_if, trust_score)
VALUES
(
  2,
  'LOGIN_ATTEMPT',
  87,
  'Fake / Bot',
  'High login frequency, Low engagement ratio, New account age, Repetitive behavior',
  'If login frequency reduced and engagement improved, risk would drop to 35%',
  42
);
