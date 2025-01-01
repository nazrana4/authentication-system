from flask import Flask, render_template, g, request, url_for, jsonify, json, redirect,
from email.message import EmailMessage
import threading, time, sqlite3
import random
import bcrypt
from datetime import datetime, timedelta
from init_db import get_db
import smtplib
from dotenv import load_dotenv
import os

load_dotenv()
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

app = Flask(__name__, template_folder="templates")
app.config['DATABASE'] = './db.sqlite'

server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login(EMAIL_USER, EMAIL_PASSWORD)

# Properly handle teardown to close the database connection
@app.teardown_appcontext
def close_db_connection(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()

# Extract session data before each request
@app.before_request
def extract_session_data():
    session_id = request.cookies.get("session_id")
    
    # No session cookie found
    if not session_id: 
        print("No session cookie")
        g.is_authenticated = False
    else:
        print(request.cookies)
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM session WHERE id = ?", (session_id,))
        session = cursor.fetchone()

        # Ensure session exists and has not expired
        if session and session['expires_at'] > datetime.now():
            g.is_authenticated = True
            g.sessionid = session_id
        else:
            if session:
                cursor.execute("DELETE FROM session WHERE id = ?", (session_id,))
                db.commit()
            g.is_authenticated = False

# Helper functions
def generate_otp(length=6):
    return ''.join(random.choices("0123456789", k=length))

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(actual_password: bytes, entered_password: str) -> bool:
    return bcrypt.checkpw(entered_password.encode('utf-8'), actual_password)

def generate_session_id(data: str) -> str:
    return f"{data}+{datetime.now().isoformat()}"

#wrapper function to restrict access based on isAuthenticated
def ensureAuthenticated(f):
    def decorated_fn(*args,**kwargs):
        print("running ensure auth")
        print(g.is_authenticated)
        if not g.get('is_authenticated') :
            return "Error : You need to Authenticate first"
        return f(*args,*kwargs)
    return decorated_fn

# Routes
@app.route('/')
def index():
    if not getattr(g, 'is_authenticated', False):
        return render_template('unauthenticated.html')
    expires=datetime.now()+timedelta(minutes=1)
    return render_template('welcome.html')

@app.route('/users')
def users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()
    # Convert the fetched data to a displayable format
    users_list = [{"id": user["id"], "name": user["name"], "email": user["email"]} for user in users]

    return jsonify({"users": users_list})

@app.route('/sessions')
def sessions():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM session")
    sessions = cursor.fetchall()
    # Convert the fetched data to a displayable format
    sessions_list = [{"id": session["id"], "data": session["data"], "expiration": session["expires_at"]} for session in sessions]

    return jsonify({"sessions": sessions_list})

@app.route('/deleteusers')
def delete():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM user")
    db.commit()
    return "Done deleted"

@app.route('/deletesessions')
def deletesession():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM session")
    db.commit()
    return "Done deleted"

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template('register.html')
    
    # Grabbing user payload from form
    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password")
    
    # Validate form fields
    if not name or not email or not password:
        return "Error: All fields are required"

    # Fetching user data from the database
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = cursor.fetchone()  
    
    # Checking if user exists
    if user is not None:
        return "Error: User with the same email already exists"
    
    # Add the new user to the database
    hashed_password = hash_password(password)
    cursor.execute("INSERT INTO user (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_password))
    db.commit()

    login_url = url_for('login')

    # Return a success message and initiate the redirect using JavaScript
    return f"""
        <div>User added successfully. You will be redirected to the login page in a few seconds.</div>
        <script>
            setTimeout(function() {{
                window.location.href = '{login_url}';
            }}, 5000);  // 5000 ms = 5 seconds
        </script>
    """
@ensureAuthenticated
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'GET':
        return render_template('change_password.html')

    email = request.form.get('email')
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        return "Error: New passwords do not match!"

    # Verify the old password
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = cursor.fetchone()

    if user is None:
        return "Error: Email not found!"

    if not verify_password(user['password'], old_password):
        return "Error: Old password is incorrect!"

    # Update to the new password
    hashed_password = hash_password(new_password)
    cursor.execute("UPDATE user SET password = ? WHERE email = ?", (hashed_password, email))
    db.commit()

    return redirect(url_for('logout'))

@ensureAuthenticated
@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template('login.html')
    
    # Grabbing users payload from form
    email = request.form.get("email")
    actual_password = request.form.get("password")
    
    # Fetching user data from db
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = cursor.fetchone()  
    
    # Checking if user exists
    if user is None:
        return jsonify({"message": f"No user exists with emailId {email}"}), 404
    
    if not verify_password(user["password"], actual_password):
        return "Incorrect Password"
    
    # Generate session ID
    session_id = generate_session_id(email)
    data = {
        "email": email,
        "username": user["name"],
        "id": user["id"]
    }
    data = json.dumps(data)
    expires_at = datetime.now() + timedelta(minutes=1)
    cursor.execute("INSERT INTO session (id, data, expires_at) VALUES (?, ?, ?)", (session_id, data, expires_at))
    db.commit()

    # Setting up response
    response = redirect(url_for('welcome'))
    expires_str = expires_at.strftime("%a, %d %b %Y %H:%M:%S GMT")
    response.set_cookie("session_id", session_id, secure=True, httponly=True, samesite="Lax", max_age=int(60 * 1))
    return response

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET': 
        return render_template('forgot_password.html')

    email = request.form.get('email')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "Email not found"}), 404
    
    otp = generate_otp()
    expires_at = datetime.now() + timedelta(minutes=5)

    cursor.execute("INSERT INTO otp (email, otp, expires_at) VALUES (?, ?, ?) ON CONFLICT(email) DO UPDATE SET otp = ?, expires_at = ?",
                   (email, otp, expires_at, otp, expires_at))
    db.commit()
    
    msg = EmailMessage()
    msg.set_content(f"Your OTP for password reset is {otp}. It will expire in 5 minutes.")  
    msg['Subject'] = 'Your OTP for Password Reset'
    msg['From'] = EMAIL_USER
    msg['To'] = email
    server.send_message(msg)

    login_url = url_for('reset_password')
    return f"""
        <div>OTP sent successfully.</div>
        <script>
            setTimeout(function() {{
                window.location.href = '{login_url}';
            }}, 2000);  
        </script>
    """


@app.route('/reset-password', methods=['GET','POST'])
def reset_password():
    if request.method == 'GET':
        return render_template('reset_password.html')
    
    email = request.form.get('email')
    otp = request.form.get('otp')
    new_password = request.form.get('password')

    # Validate OTP
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM otp WHERE email = ? AND otp = ?", (email, otp))
    otp_record = cursor.fetchone()
    
    if not otp_record:
        return jsonify({"error": "Invalid OTP"}), 400
    
    exp_time = datetime.strptime(otp_record['expires_at'], '%Y-%m-%d %H:%M:%S.%f')
    if datetime.now() > exp_time:
        return jsonify({"error": "OTP has expired"}), 400
    
    if otp != otp_record['otp']:
        return "Wrong OTP"
    
    # Update the user's password
    hashed_password = hash_password(new_password)
    cursor.execute("UPDATE user SET password = ? WHERE email = ?", (hashed_password, email))
    db.commit()

    # Delete OTP from the database
    cursor.execute("DELETE FROM otp WHERE email = ?", (email,))
    db.commit()

    login_url = url_for('login')
    return f"""
        <div>Password reset successfully.</div>
        <script>
            setTimeout(function() {{
                window.location.href = '{login_url}';
            }}, 2000);  // 5000 ms = 2 seconds
        </script>
    """


@ensureAuthenticated
@app.route("/logout")
def logout():
    print("Logging out")
    session_id = getattr(g, 'sessionid', None)
    if session_id:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE from session WHERE id = ?", (session_id,))
        db.commit()
    
    # After logout, redirect to the home page or login page
    response = redirect(url_for('index'))  # Or you can redirect to 'login' or another page
    response.delete_cookie("session_id")  # Remove the session cookie as well
    return response

def delete_expired_sessions():
    while True:
        print("Thread is running...")
       
        db = sqlite3.connect('./db.sqlite')
        db.row_factory = sqlite3.Row 
        cursor = db.cursor()
        time_now = datetime.now()
        print(time_now)
        cursor.execute("DELETE FROM session WHERE expires_at <= ?", (time_now,))
        deleted_count = cursor.rowcount 
        db.commit()
        if deleted_count > 0:
                print(f"{deleted_count} record(s) deleted from session table")
        cursor.execute("DELETE FROM otp WHERE expires_at <= ?", (time_now,))
        deleted_count = cursor.rowcount 
        db.commit()
        if deleted_count > 0:
                print(f"{deleted_count} record(s) deleted from otp table")
        db.close()

        time.sleep(60*60*24) 

def start_thread():
    thread = threading.Thread(target=delete_expired_sessions, daemon=True)
    thread.start()

if __name__ == '__main__':
    start_thread()
    app.run(debug=True)