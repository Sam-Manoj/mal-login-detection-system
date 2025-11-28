import os
import random
import json
from datetime import datetime, timezone, timedelta 
import pandas as pd

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from flask_socketio import SocketIO, emit, join_room 

# --- Import your Bayesian Network (BN) functions ---
# (Make sure pgm_model.py is in the same directory)
from pgm_model import (
    make_synthetic_data, 
    prepare_and_discretize, 
    get_default_model_structure, 
    train_bn, 
    score_evidence
)

# --- App Configuration ---

db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'app.db')

# --- MODIFIED: Point to new template and static folders ---
app = Flask(__name__,
            template_folder='templates',
            static_folder='static')

app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)

# --- Global variable to hold the trained BN inference engine ---
BN_INFER = None

# --- In-memory tracker for failed login attempts ---
FAILED_ATTEMPTS_DB = {}
LOCKOUT_DURATION = timedelta(minutes=15) # Failures are forgotten after 15 mins

# --- Database Models (Unchanged) ---

class User(db.Model):
    """Stores user accounts and their roles."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), nullable=False) # e.g., 'employee', 'manager', 'it', 'admin'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LoginAttempt(db.Model):
    """Logs every login attempt for the admin to review."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(50), nullable=True)
    login_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address = db.Column(db.String(50))
    vpn_used = db.Column(db.Boolean)
    risk_score = db.Column(db.Integer)
    is_malicious = db.Column(db.Boolean, default=False)
    location_data = db.Column(db.Text, nullable=True) # Stores formatted string
    lat = db.Column(db.Float, nullable=True)
    lon = db.Column(db.Float, nullable=True)
    
    user = db.relationship('User', backref=db.backref('login_attempts', lazy=True))

# --- Bayesian Network Risk Analysis (Unchanged) ---

def create_evidence_from_request(
    login_time_utc: datetime, 
    vpn_used: bool, 
    failed_attempts_count: int 
) -> dict:
    """
    Converts raw login data into the discrete evidence categories
    your Bayesian Network expects.
    """
    evidence = {}
    evidence['ip_risk'] = 2 if vpn_used else 0
    evidence['device_unknown'] = 1 if vpn_used else 0
    hour = login_time_utc.hour
    if 8 <= hour < 18:
        evidence['time_dev'] = 0
    elif 6 <= hour < 8 or 18 <= hour < 23:
        evidence['time_dev'] = 1
    else:
        evidence['time_dev'] = 2
    evidence['velocity'] = 0
    if failed_attempts_count == 0:
        evidence['failed_attempts'] = 0
    elif 1 <= failed_attempts_count <= 2:
        evidence['failed_attempts'] = 1
    else:
        evidence['failed_attempts'] = 2
    print(f"Generated Evidence for BN: {evidence}")
    return evidence


def calculate_bayesian_risk(
    login_time_utc: datetime, 
    vpn_used: bool, 
    failed_attempts_count: int 
) -> int:
    """
    Calculates the risk score using the pre-trained Bayesian Network.
    Returns an integer score (0-100).
    """
    global BN_INFER
    if BN_INFER is None:
        print("CRITICAL ERROR: Bayesian Network is not trained!")
        return 50 
    
    evidence = create_evidence_from_request(
        login_time_utc, 
        vpn_used, 
        failed_attempts_count
    )
    
    try:
        prob_malicious = score_evidence(BN_INFER, evidence)
    except Exception as e:
        print(f"Error during BN scoring: {e}")
        print(f"Failed evidence was: {evidence}")
        return 50 # Fallback score

    risk_score = int(prob_malicious * 100)
    print(f"P(malicious)={prob_malicious:.4f} -> Risk Score: {risk_score}")
    return risk_score


# --- Geolocation Service (Unchanged) ---

def get_ip_geolocation(ip_address):
    default_response = {
        "formatted_string": "Local Address (No lookup)",
        "lat": None,
        "lon": None
    }
    
    if ip_address == '127.0.0.1':
        print("Local IP detected, simulating lookup for 8.8.8.8 (Google DNS)")
        ip_address = '8.8.8.8' 
        default_response['formatted_string'] = "Local Address (Used 8.8.8.8 for Demo)"
    
    if not ip_address:
         return default_response
         
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,lat,lon,isp,org,mobile,proxy"
        response = requests.get(url, timeout=5)
        response.raise_for_status() 
        data = response.json()
        
        if data.get('status') == 'success':
            location_info = (
                f"Country/City: {data.get('country', 'N/A')} / {data.get('city', 'N/A')}\n"
                f"Coordinates: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}\n"
                f"ISP: {data.get('isp', 'N/A')}\n"
                f"Organization: {data.get('org', 'N/A')}\n"
                f"Proxy/VPN: {data.get('proxy', 'N/A')}\n"
                f"Mobile Network: {data.get('mobile', 'N/A')}"
            )
            
            if data.get('mobile'):
                location_info += "\n\n*** ATTENTION: Mobile Network Detected. ***"
                         
            return {
                "formatted_string": location_info,
                "lat": data.get('lat'),
                "lon": data.get('lon')
            }
        else:
            return {"formatted_string": f"Geo-IP lookup failed: {data.get('message', 'Unknown error')}", "lat": None, "lon": None}
            
    except requests.RequestException as e:
        print(f"Error fetching Geo-IP: {e}")
        return {"formatted_string": f"Error fetching Geo-IP: {e}", "lat": None, "lon": None}
    except Exception as e:
        print(f"An unexpected error occurred in get_ip_geolocation: {e}")
        return {"formatted_string": "Unexpected error during Geo-IP lookup.", "lat": None, "lon": None}

# --- Helper Functions ---

def is_admin():
    """Checks if the currently logged-in user is an admin."""
    return session.get('role') == 'admin'

def setup_database():
    """Initializes the database with tables and default users."""
    print("Setting up database...")
    with app.app_context():
        db.create_all()
        
        # --- MODIFIED: Only create the admin user by default ---
        if User.query.filter_by(username='admin').first() is None:
            print("Creating default admin user...")
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('admin123')
            db.session.add(admin_user)
        
        # --- NEW: Add other users if they don't exist, for testing ---
        if User.query.filter_by(username='employee').first() is None:
            print("Creating default employee user...")
            emp_user = User(username='employee', role='employee')
            emp_user.set_password('employee123')
            db.session.add(emp_user)
            
        if User.query.filter_by(username='manager').first() is None:
            print("Creating default manager user...")
            mgr_user = User(username='manager', role='manager')
            mgr_user.set_password('manager123')
            db.session.add(mgr_user)

        db.session.commit()
    print("Database setup complete.")


# --- Flask Routes ---

@app.route('/')
def index():
    # --- MODIFIED: Renders the new "About" page (was about.html) ---
    return render_template('index.html')

# --- NEW: Route for the Info page ---
@app.route('/info')
def info():
    return render_template('info.html')

# --- REMOVED: /register route ---
# --- REMOVED: /dashboard route (user-facing) ---
# --- REMOVED: /view_location route (no longer linked from new dashboard) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # --- MODIFIED: VPN data is no longer collected on the new login form ---
        # We'll default it to False. The BN model can handle this.
        vpn_used = False 
        
        # --- Check for recent failed attempts (Unchanged) ---
        now = datetime.now(timezone.utc)
        current_failures = 0
        user_failure_data = FAILED_ATTEMPTS_DB.get(username)

        if user_failure_data:
            time_since_last_fail = now - user_failure_data['last_attempt_time']
            if time_since_last_fail > LOCKOUT_DURATION:
                current_failures = 0
                if username in FAILED_ATTEMPTS_DB:
                    del FAILED_ATTEMPTS_DB[username]
            else:
                current_failures = user_failure_data['count']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # --- SUCCESSFUL LOGIN ---
            
            # We read `current_failures` *before* this successful login.
            
            # Clear any existing failure record for this user
            if username in FAILED_ATTEMPTS_DB:
                del FAILED_ATTEMPTS_DB[username]
                
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            if user.role == 'admin':
                # Admin is logged in and redirected to the admin dashboard
                return redirect(url_for('admin_dashboard'))

            # --- MODIFIED: NEW LOGIC FOR ALL SUCCESSFUL (NON-ADMIN) LOGINS ---
            
            print(f"User '{username}' logged in successfully.")
            
            if 'X-Forwarded-For' in request.headers:
                ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            else:
                ip_address = request.remote_addr
            
            login_time = datetime.now(timezone.utc)
            risk_score = 0
            is_malicious = False

            if current_failures < 3:
                # --- Case 1: "Trusted" login (0, 1, or 2 prior failures) ---
                print(f"User '{username}' has < 3 failures. Logging as 'Allowed'.")
                # Assign a simple low risk score for trusted users
                risk_score = 10 
                is_malicious = False

            else:
                # --- Case 2: "Suspicious" login (3 or more prior failures) ---
                # Log this successful login, but run it through the BN first.
                print(f"User '{username}' has >= 3 failures. Performing full analysis.")
                
                # Run the full analysis
                risk_score = calculate_bayesian_risk(
                    login_time, 
                    vpn_used, 
                    current_failures # Pass the failure count as evidence
                )
                is_malicious = risk_score > 75 
            
            location_data_dict = get_ip_geolocation(ip_address)
            
            # --- Create the database entry FOR ALL successful logins ---
            attempt = LoginAttempt(
                user_id=user.id,
                username=user.username,
                role=user.role,
                ip_address=ip_address,
                vpn_used=vpn_used,
                risk_score=risk_score, # Use the calculated or assigned score
                is_malicious=is_malicious,
                location_data=location_data_dict['formatted_string'],
                lat=location_data_dict['lat'],
                lon=location_data_dict['lon']
            )
            db.session.add(attempt)
            db.session.commit()
            
            # --- Broadcast the "Successful" login attempt ---
            try:
                login_data = {
                    "id": attempt.id,
                    "login_time": attempt.login_time.strftime('%Y-%m-%d %H:%M:%S'),
                    "username": attempt.username,
                    "role": attempt.role,
                    "ip_address": attempt.ip_address,
                    "vpn_used": attempt.vpn_used,
                    "risk_score": attempt.risk_score,
                    "location_data": attempt.location_data,
                    "is_malicious": attempt.is_malicious,
                    "lat": attempt.lat,
                    "lon": attempt.lon
                }
                socketio.emit('new_login', login_data, to='admin_room')
                print(f"Emitted 'new_login' (SUCCESSFUL) event for {username} to admin_room")
            except Exception as e:
                print(f"Error emitting socket event: {e}")
            
            flash('You have been logged in successfully.', 'success')
            return redirect(url_for('index'))
            
            # --- END OF MODIFIED SUCCESS LOGIC ---

        else:
            # --- FAILED LOGIN ---
            new_count = current_failures
            if username:
                new_count = current_failures + 1
                FAILED_ATTEMPTS_DB[username] = {
                    'count': new_count,
                    'last_attempt_time': now
                }
                print(f"Failed login for '{username}'. New count: {new_count}")

            # --- MODIFIED: Log failures to the dashboard ---
            # Log when failures reach 2 (medium/flagged) or 3+ (high/malicious)
            if username and new_count >= 2:
                print(f"Failure count ({new_count}) >= 2. Logging failed attempt for '{username}' to database.")
                
                if 'X-Forwarded-For' in request.headers:
                    ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
                else:
                    ip_address = request.remote_addr
                
                user_id = user.id if user else 0 
                user_role = user.role if user else "Unknown"

                # Medium flag for exactly 2 failures, high risk for 3 or more
                if new_count == 2:
                    failure_risk_score = 50
                    is_malicious_flag = False
                    print(f"Marking attempt for '{username}' as MEDIUM (risk={failure_risk_score}).")
                else:
                    failure_risk_score = 99
                    is_malicious_flag = True
                    print(f"Marking attempt for '{username}' as HIGH/MALICIOUS (risk={failure_risk_score}).")

                location_data_dict = get_ip_geolocation(ip_address)

                try:
                    attempt = LoginAttempt(
                        user_id=user_id,
                        username=username, 
                        role=user_role,
                        ip_address=ip_address,
                        vpn_used=vpn_used,
                        risk_score=failure_risk_score,
                        is_malicious=is_malicious_flag,
                        location_data=location_data_dict['formatted_string'],
                        lat=location_data_dict['lat'],
                        lon=location_data_dict['lon']
                    )
                    db.session.add(attempt)
                    db.session.commit()
                    
                    # --- Broadcast the FAILED login attempt to admins ---
                    login_data = {
                        "id": attempt.id,
                        "login_time": attempt.login_time.strftime('%Y-%m-%d %H:%M:%S'),
                        "username": attempt.username,
                        "role": attempt.role,
                        "ip_address": attempt.ip_address,
                        "vpn_used": attempt.vpn_used,
                        "risk_score": attempt.risk_score,
                        "location_data": attempt.location_data,
                        "is_malicious": attempt.is_malicious,
                        "lat": attempt.lat,
                        "lon": attempt.lon
                    }
                    socketio.emit('new_login', login_data, to='admin_room')
                    print(f"Emitted 'new_login' (FAILURE) event for {username} to admin_room")

                except Exception as e:
                    print(f"Error logging failed attempt: {e}")
                    db.session.rollback()
            # --- END OF MODIFIED FAILURE LOGIC ---

            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
    
    # --- MODIFIED: Renders the new "Login" page (was index.html) ---
    return render_template('login.html')

@app.route('/admin')
def admin_dashboard():
    if not is_admin():
        # --- MODIFIED: If not admin, redirect to login page ---
        flash('You must be an admin to access this page.', 'error')
        return redirect(url_for('login'))
        
    all_attempts = LoginAttempt.query.order_by(LoginAttempt.login_time.desc()).all()
    
    # --- NEW: Calculate initial statistics ---
    stats = {
        'total': len(all_attempts),
        'blocked': 0,
        'flagged': 0,
        'allowed': 0
    }
    
    for attempt in all_attempts:
        if attempt.risk_score > 75:
            stats['blocked'] += 1
        elif attempt.risk_score > 40:
            stats['flagged'] += 1
        else:
            stats['allowed'] += 1
    # --- END OF NEW STATS LOGIC ---
    
    # --- MODIFIED: Renders the new "Admin" page and passes stats ---
    return render_template('admin_dashboard.html', attempts=all_attempts, stats=stats)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# --- SocketIO Event Handlers (Unchanged) ---

@socketio.on('connect')
def handle_connect():
    if is_admin():
        join_room('admin_room')
        print(f"Admin user {session.get('username')} connected and joined 'admin_room'.")
    else:
        print(f"Non-admin user {session.get('username', 'Guest')} connected.")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client {session.get('username', 'Guest')} disconnected.")


# --- Main Entry Point ---

if __name__ == '__main__':
    if not os.path.exists(db_path):
        setup_database()
        
    # --- Train the Bayesian Network on Startup ---
    print("--- Training Bayesian Network (This may take a moment) ---")
    
    # --- MODIFIED: Will look for the clean CSV file ---
    dataset_path = 'synthetic_dataset_for_training.csv'
    df_train = None

    if not os.path.exists(dataset_path):
        print(f"--- WARNING: Dataset file not found at {dataset_path}")
        print(f"---          Please run 'python pgm_model.py' first to generate it.")
        print("---          Falling back to synthetic data for this session.")
        df_train = make_synthetic_data(3000)
    else:
        try:
            print(f"--- Loading training data from {dataset_path}...")
            # --- MODIFIED: Added encoding='utf-8' for robustness ---
            df_train = pd.read_csv(dataset_path, encoding='utf-8')
            required_cols = {'malicious', 'ip_risk', 'device_unknown', 'time_dev', 'velocity', 'failed_attempts'}
            if not required_cols.issubset(df_train.columns):
                print(f"--- WARNING: CSV file is missing required columns. Needs: {required_cols}")
                print("---          Falling back to synthetic data.")
                df_train = make_synthetic_data(3000)
            else:
                print("---          Successfully loaded training data from CSV. ---")
        except Exception as e:
            print(f"--- ERROR: Failed to load CSV: {e}")
            print("---          Falling back to synthetic data.")
            df_train = make_synthetic_data(3000)
    
    df_prep = prepare_and_discretize(df_train)
    model = get_default_model_structure()
    fitted_model, BN_INFER = train_bn(df_prep, model)
    print("--- Bayesian Network trained and ready. ---")
    # --- End of BN Training ---
        
    print("\n--- Flask App Running with SocketIO ---")
    print(f"Database is at: {db_path}")
    print("Default accounts:")
    print("   Admin:       admin / admin123")
    print("   Employee:    employee / employee123")
    print("   Manager:     manager / manager123")
    print("Access the app at: http://127.0.0.1:5000")
    print("---------------------------------------\n")
    
    socketio.run(app, debug=True)