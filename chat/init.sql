-- Use the specified database (Replace 'chatdb' with your actual database name if different)
USE chatdb;

-- Drop tables if they already exist (to avoid conflicts during development/testing)
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS users;


-- Create 'users' table
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- In a real application, this should store hashed passwords, not plain text
    recoverykey VARCHAR(255) NOT NULL,
    ratelimit INT,
    limitTime TIMESTAMP ,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create 'messages' table
CREATE TABLE messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    message_text TEXT NOT NULL,
    iv TEXT NOT NULL,
    tag TEXT NOT NULL,
    second_tag TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);

-- Optionally, insert some initial data for testing
-- In the following, the password for Alice is "password123", and "password456" for Bob
INSERT INTO users (username, password,recoverykey,ratelimit) VALUES ('Alice', '$2b$12$D8b8aDwVo7sd/UX340zZxOHdzeQKrOXl4xoPVVZveEM2.t86y39tK','AliceInTheWonderLand',0); -- Use hashed passwords in production
INSERT INTO users (username, password,recoverykey,ratelimit) VALUES ('Bob', '$2b$12$VwVwYqTk7z4l/BvSs04GdOgEgzyW3h4vC1eaRY7kEsEMDigerBUL.','SpongeBobSquarePants',0); -- Use hashed passwords in production
