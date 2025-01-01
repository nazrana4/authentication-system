# Authentication System

## Overview
This project is a **Flask-based authentication system** that provides user registration, login, password reset, and session management functionalities. It includes database integration using SQLite and features email-based OTP verification for enhanced security.

## Features
- **User Registration**: Allows new users to create accounts.
- **Login and Session Management**: Authenticated sessions with cookie-based session IDs.
- **Password Management**: Includes options to change or reset passwords.
- **Email Verification**: Sends OTP via email for password recovery.
- **Database Integration**: Uses SQLite for storing user data and sessions.
- **Security Features**:
  - Password hashing with bcrypt.
  - Secure session cookies with expiration.
- **Automatic Cleanup**: Deletes expired sessions and OTP entries periodically.

## Project Structure
```
.
├── app.py           # Main application logic and routes
├── init_db.py       # Database initialization and connection handling
├── templates/       # HTML templates for rendering web pages
├── static/          # Static files (CSS, JS, etc.)
├── schema.sql       # Database schema for tables
├── .env             # Environment variables for email credentials
├── requirements.txt # Project dependencies
```

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/nazrana4/authentication-system.git
cd authentication-system
```

### 2. Create a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the root directory with the following:
```
EMAIL_USER=your-email@example.com
EMAIL_PASSWORD=your-email-password
```

### 5. Initialize the Database
```bash
python init_db.py
```

### 6. Run the Application
```bash
python app.py
```
Access the application at: `http://127.0.0.1:5000`

## API Endpoints

### User Management
- **Register**: `POST /register`
- **Login**: `POST /login`
- **Logout**: `GET /logout`
- **Change Password**: `POST /change-password`
- **Forgot Password**: `POST /forgot-password`
- **Reset Password**: `POST /reset-password`

### Admin Actions
- **View Users**: `GET /users`
- **View Sessions**: `GET /sessions`
- **Delete Users**: `GET /deleteusers`
- **Delete Sessions**: `GET /deletesessions`

## Security Measures
- **Password Hashing**: All passwords are hashed before storage using bcrypt.
- **Session Expiry**: Sessions expire after 1 minute of inactivity.
- **Cookie Security**: Secure, HttpOnly cookies to prevent XSS attacks.
- **Email Verification**: OTP-based email verification for password reset.

## Future Enhancements
- Implement multi-factor authentication.
- Add support for OAuth providers (Google, Facebook).
- Improve logging and error handling.

## Author
**Nazrana**  
GitHub: [nazrana4](https://github.com/nazrana4)

