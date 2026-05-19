# Secure Login System

A Node.js, Express, MySQL, and EJS secure login web app with hashed passwords, input validation, SQL injection protection, session management, logout, CSRF protection, login rate limiting, HTTPS, and authenticator-app based two-factor authentication.

## Features

- User registration and login
- Password hashing with bcrypt
- Parameterized MySQL queries
- Server-side and client-side validation
- Session-based authentication
- Logout
- CSRF protection
- Helmet security headers
- Login rate limiting
- Authenticator app 2FA using TOTP

## Setup

Install dependencies:

```powershell
npm install
```

Create your local environment file:

```powershell
copy .env.example .env
```

Update `.env` with your MySQL password and a long random session secret.

Create the database and table:

```sql
SOURCE database.sql;
```

Or run the SQL inside `database.sql` manually in MySQL Workbench.

## HTTPS Certificates

The app expects local SSL files at:

```text
ssl/server.key
ssl/server.cert
```

These files are ignored by Git because they are machine-specific.

## Run

```powershell
npm start
```

Open:

```text
https://localhost:3000
```

Your browser may warn about the local self-signed certificate. For local testing, choose the advanced option and continue.

## 2FA Flow

After the first successful password login, the user is redirected to the 2FA setup page. Scan the QR code with Google Authenticator, Microsoft Authenticator, Authy, or another TOTP app. Future logins require the 6-digit authenticator code.
