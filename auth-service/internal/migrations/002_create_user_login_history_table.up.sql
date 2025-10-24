-- Create user login history table
CREATE TABLE IF NOT EXISTS user_login_history (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    ip_address VARCHAR(45) NOT NULL, -- IPv4 (15 chars) or IPv6 (39 chars)
    user_agent TEXT,
    login_status VARCHAR(20) NOT NULL CHECK (login_status IN ('success', 'failed', 'blocked')),
    failure_reason VARCHAR(100), -- Only populated when login_status = 'failed'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_login_history_user_id ON user_login_history(user_id);
CREATE INDEX IF NOT EXISTS idx_user_login_history_ip_address ON user_login_history(ip_address);
CREATE INDEX IF NOT EXISTS idx_user_login_history_status ON user_login_history(login_status);
CREATE INDEX IF NOT EXISTS idx_user_login_history_created_at ON user_login_history(created_at);
CREATE INDEX IF NOT EXISTS idx_user_login_history_user_status ON user_login_history(user_id, login_status);
