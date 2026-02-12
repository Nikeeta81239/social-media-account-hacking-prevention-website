-- Insert users
INSERT INTO users (email, password, role) VALUES
('admin123@gmail.com', 'admin123@#', 'admin'),
('user123@gmail.com', 'user123@#', 'user');


-- Insert into blocked_users
INSERT INTO blocked_users (user_id, reason)
VALUES (2, 'Multiple suspicious login attempts');

-- Insert into attack_logs
INSERT INTO attack_logs (user_id, ip_address, risk_score, status)
VALUES
(2, '203.0.113.45', 87, 'SUSPICIOUS');

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
