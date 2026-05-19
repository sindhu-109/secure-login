CREATE DATABASE IF NOT EXISTS secure_app;

USE secure_app;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(30) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    two_factor_secret VARCHAR(255),
    two_factor_enabled BOOLEAN DEFAULT false
);
