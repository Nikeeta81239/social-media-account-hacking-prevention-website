CREATE DATABASE ai_social_security;
USE ai_social_security;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

 
 CREATE TABLE blocked_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    reason VARCHAR(100),
    blocked_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(50),
    location VARCHAR(50),
    device VARCHAR(50),
    status VARCHAR(20),
    risk VARCHAR(10),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE attack_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  ip_address VARCHAR(50),
  risk_score INT,
  status VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE xai_explanations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  event_type VARCHAR(50),
  risk_score INT,
  decision VARCHAR(50),
  top_reasons TEXT,
  what_if TEXT,
  trust_score INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
