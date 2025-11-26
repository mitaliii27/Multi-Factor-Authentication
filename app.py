import os
import threading
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'spa.firstone@gmail.com'
app.config['MAIL_PASSWORD'] = 'qhmw woqe cwbw gqkz'  # App password from email_service.py
app.config['MAIL_DEFAULT_SENDER'] = 'spa.firstone@gmail.com'

# Initialize extensions
mail = Mail(app)

# Import other modules after app initialization to avoid circular imports
from auth import authenticate_user, verify_totp, send_totp, check_panic_password, lock_account, is_account_locked
from location import verify_location
from crypto import generate_keys, encrypt_message, decrypt_message, sign_message, verify_signature
from email_service import send_panic_alert, send_lock_alert

# User data storage (in production, this would be a database)
user_data = {
    "user123": {
        "password": "123",
        "panic_password": "p123",
        "email": "willycryptoproj@gmail.com",
        "login_attempts": 0,
        "locked_until": None,
        "session_start": None,
        "keys": None,
        "role": "user"
    },
    "admin": {
        "password": "pwd",
        "panic_password": "ppwd",
        "email": "willycryptoproj@gmail.com",
        "login_attempts": 0,
        "locked_until": None,
        "session_start": None,
        "keys": None,
        "role": "admin"
    }
}

@app.context_processor
def inject_user_data():
    return dict(user_data=user_data)


alert_email = "willycryptoproj@gmail.com"

# Session management data
active_sessions = {}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if username exists
        if username not in user_data:
            flash("Invalid username or password", "danger")
            return render_template('login.html')
        
        # Check if account is locked
        if is_account_locked(user_data, username):
            locked_until = user_data[username]["locked_until"]
            return render_template('locked.html', username=username, locked_until=locked_until)
        
        # Check for panic password
        if check_panic_password(user_data, username, password):
            logger.debug("Panic password detected. Showing decoy dashboard.")
            # Send panic alert asynchronously
            threading.Thread(target=send_panic_alert, args=(
                mail, username, datetime.now())).start()
            
            # Use the same decoy dashboard for all users (admin or regular)
            return render_template('decoy_dashboard.html', username=username)
        
        # Normal authentication
        auth_result = authenticate_user(user_data, username, password)
        if auth_result == "success":
            # Reset login attempts on successful authentication
            user_data[username]["login_attempts"] = 0
            
            # Store the username in session for the next steps
            session['username'] = username
            
            # First check location before proceeding to TOTP
            return redirect(url_for('verify_location_route'))
        else:
            if auth_result == "locked":
                locked_until = user_data[username]["locked_until"]
                return render_template('locked.html', username=username, locked_until=locked_until)
            else:
                flash("Invalid username or password", "danger")
    
    return render_template('login.html')

@app.route('/totp', methods=['GET', 'POST'])
def verify_totp_route():
    if 'username' not in session or 'totp_code' not in session:
        flash("Session expired. Please login again.", "danger")
        return redirect(url_for('login'))
    
    username = session['username']
    
    if request.method == 'POST':
        totp_input = request.form.get('totp')
        
        # Verify the TOTP
        if verify_totp(session.get('totp_code'), totp_input, session.get('totp_expiry')):
            # TOTP verified, proceed directly to dashboard instead of location verification
            # Generate ECC keys for secure communication
            private_key, public_key = generate_keys()
            user_data[username]["keys"] = {
                "private_key": private_key,
                "public_key": public_key
            }
            
            # Set session start time
            session_start = datetime.now()
            user_data[username]["session_start"] = session_start
            session['session_start'] = session_start.timestamp()
            
            # Store encrypted session data
            session['logged_in'] = True
            session['username'] = username
            
            # If user is admin, redirect to admin dashboard, otherwise to user dashboard
            if user_data[username]["role"] == "admin":
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid or expired TOTP code", "danger")
    
    return render_template('totp.html', username=username)

@app.route('/verify-location', methods=['GET', 'POST'])
def verify_location_route():
    if 'username' not in session:
        flash("Session expired. Please login again.", "danger")
        return redirect(url_for('login'))
    
    username = session['username']
    client_ip = request.remote_addr
    
    # Get location info first
    location_info = verify_location(client_ip)
    
    # Check if location is from India
    if request.method == 'POST':
        # User has confirmed their location
        confirmation = request.form.get('confirm_location', 'no')
        
        # Only proceed if the IP is from India and user confirmed
        if confirmation == 'yes' and location_info.get('is_india', False):
            # Generate TOTP and send it for the next verification step
            totp_code = send_totp(mail, user_data[username]["email"])
            session['totp_code'] = totp_code
            session['totp_expiry'] = (datetime.now() + timedelta(minutes=5)).timestamp()
            
            # Proceed to TOTP verification
            return redirect(url_for('verify_totp_route'))
        else:
            # Either not from India or user cancelled
            if not location_info.get('is_india', False):
                flash("Access denied: Your location appears to be outside India. This application is only available in India.", "danger")
            else:
                flash("Location verification failed. Please try again.", "danger")
            
            # Clear session and redirect to login
            session.clear()
            return redirect(url_for('login'))
    
    # Display the location verification page
    return render_template('location_verify.html', username=username, location=location_info)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        flash("You must be logged in to access the dashboard", "danger")
        return redirect(url_for('login'))
    
    username = session.get('username')
    
    # Check if session has expired (6 hours)
    current_time = datetime.now()
    session_start = datetime.fromtimestamp(session.get('session_start', 0))
    if (current_time - session_start).total_seconds() > 6 * 3600:
        # Session expired
        session.clear()
        flash("Your session has expired. Please login again.", "info")
        return redirect(url_for('login'))
    
    # If user is admin, redirect to admin dashboard
    if user_data[username]["role"] == "admin":
        return redirect(url_for('admin_dashboard'))
    
    # If we reach here, the session is valid
    # In a real application, we would decrypt and display sensitive data here
    # using the ECC encryption
    
    # Sample encrypted data for demonstration
    private_key = user_data[username]["keys"]["private_key"]
    public_key = user_data[username]["keys"]["public_key"]
    
    # Simulate encrypted communication
    original_message = "Sensitive account information"
    encrypted_message = encrypt_message(original_message, public_key)
    signature = sign_message(original_message, private_key)
    decrypted_message = decrypt_message(encrypted_message, private_key)
    signature_valid = verify_signature(original_message, signature, public_key)
    
    # Format encrypted message for display
    encrypted_display = str(encrypted_message)
    if len(encrypted_display) > 50:
        encrypted_display = encrypted_display[:50] + "..."
    
    return render_template(
        'dashboard.html', 
        username=username, 
        session_start=session_start,
        session_expires=session_start + timedelta(hours=6),
        crypto_info={
            "encrypted": encrypted_display,
            "decrypted": decrypted_message,
            "signature_valid": signature_valid
        }
    )
    
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        flash("You must be logged in to access the admin dashboard", "danger")
        return redirect(url_for('login'))
    
    username = session.get('username')
    
    # Check if user is admin
    if user_data[username]["role"] != "admin":
        flash("You do not have permission to access the admin dashboard", "danger")
        return redirect(url_for('dashboard'))
    
    # Check if session has expired (6 hours)
    current_time = datetime.now()
    session_start = datetime.fromtimestamp(session.get('session_start', 0))
    if (current_time - session_start).total_seconds() > 6 * 3600:
        # Session expired
        session.clear()
        flash("Your session has expired. Please login again.", "info")
        return redirect(url_for('login'))
    
    # Get all users for admin
    all_users = [username for username in user_data.keys()]
    
    # Sample encrypted data for demonstration
    private_key = user_data[username]["keys"]["private_key"]
    public_key = user_data[username]["keys"]["public_key"]
    
    # Simulate encrypted communication
    original_message = "Sensitive admin information"
    encrypted_message = encrypt_message(original_message, public_key)
    signature = sign_message(original_message, private_key)
    decrypted_message = decrypt_message(encrypted_message, private_key)
    signature_valid = verify_signature(original_message, signature, public_key)
    
    # Format encrypted message for display
    encrypted_display = str(encrypted_message)
    if len(encrypted_display) > 50:
        encrypted_display = encrypted_display[:50] + "..."
    
    return render_template(
        'admin_dashboard.html', 
        username=username, 
        users=all_users,
        user_data=user_data,  # Pass user_data to the template
        session_start=session_start,
        session_expires=session_start + timedelta(hours=6),
        crypto_info={
            "encrypted": encrypted_display,
            "decrypted": decrypted_message,
            "signature_valid": signature_valid
        }
    )

@app.route('/send_message', methods=['POST'])
def send_message():
    if not session.get('logged_in'):
        return {"error": "Unauthorized"}, 401
    
    username = session.get('username')
    message_text = request.form.get('message')
    recipient = request.form.get('recipient', 'admin')  # Default recipient is admin
    
    if not message_text:
        return {"error": "Message cannot be empty"}, 400
    
    # Get user's keys for signing
    private_key = user_data[username]["keys"]["private_key"]
    public_key = user_data[username]["keys"]["public_key"]
    
    # Get recipient's keys for encryption
    if recipient not in user_data:
        return {"error": "Invalid recipient"}, 400
    
    recipient_public_key = user_data[recipient]["keys"]["public_key"]
    
    # Encrypt message with recipient's public key and sign with user's private key
    encrypted_message = encrypt_message(message_text, recipient_public_key)
    signature = sign_message(message_text, private_key)
    
    # Create message timestamp once to keep it consistent
    message_timestamp = datetime.now()
    
    # Only store the message once in each place
    
    # Store in user's own messages (as an outgoing message)
    if "messages" not in user_data[username]:
        user_data[username]["messages"] = []
    
    # This message appears in the sender's list with recipient info
    message_data = {
        "text": message_text,
        "encrypted": encrypted_message,
        "signature": signature,
        "timestamp": message_timestamp,
        "recipient": recipient,
        "type": "outgoing"  # Mark as outgoing to avoid duplication
    }
    
    user_data[username]["messages"].append(message_data)
    
    # Store the message in the recipient's messages (as an incoming message)
    if "messages" not in user_data[recipient]:
        user_data[recipient]["messages"] = []
    
    # Add to recipient's messages
    user_data[recipient]["messages"].append({
        "text": message_text,
        "encrypted": encrypted_message,
        "signature": signature,
        "timestamp": message_timestamp,
        "sender": username,  # Mark who sent this message
        "type": "incoming"   # Mark as incoming to avoid duplication
    })
    
    return {"success": True, "message": "Message sent securely"}, 200

@app.route('/get_messages')
def get_messages():
    if not session.get('logged_in'):
        return {"error": "Unauthorized"}, 401
    
    username = session.get('username')
    
    # Get the user's messages
    messages = user_data[username].get("messages", [])
    
    # For each message, verify signature and decrypt
    processed_messages = []
    
    # Create a seen set to track message ids and avoid duplication
    seen_timestamps = set()
    
    for msg in messages:
        # Skip duplicate messages
        msg_timestamp_str = msg["timestamp"].strftime('%Y-%m-%d %H:%M:%S')
        msg_identifier = f"{msg_timestamp_str}_{msg.get('text', '')}"
        
        if msg_identifier in seen_timestamps:
            continue
            
        seen_timestamps.add(msg_identifier)
        
        private_key = user_data[username]["keys"]["private_key"]
        public_key = user_data[username]["keys"]["public_key"]
        
        # Verify signature (in a real app, this would verify the sender's signature)
        signature_valid = verify_signature(msg["text"], msg["signature"], public_key)
        
        # Decrypt message (in a real app, this would decrypt messages from other users)
        decrypted = msg["text"]  # Already have plaintext for demo
        
        # Determine the real sender and recipient
        message_type = msg.get("type", "unknown")
        
        if message_type == "outgoing":
            # This is a message sent by the current user
            actual_sender = username
            actual_recipient = msg.get("recipient", "unknown")
        elif message_type == "incoming":
            # This is a message received by the current user
            actual_sender = msg.get("sender", "unknown")
            actual_recipient = username
        else:
            # Default case, use the values from the message
            actual_sender = msg.get("sender", username)
            actual_recipient = msg.get("recipient", "unknown")
        
        # Extract message metadata
        message_data = {
            "text": decrypted,
            "signature_valid": signature_valid,
            "timestamp": msg_timestamp_str,
            "sender": actual_sender,
            "recipient": actual_recipient,
            "type": message_type
        }
            
        processed_messages.append(message_data)
    
    # Sort messages by timestamp (newest first)
    processed_messages.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return {"messages": processed_messages}, 200

@app.route('/admin/get_user_messages')
def get_user_messages():
    if not session.get('logged_in'):
        return {"error": "Unauthorized"}, 401
    
    username = session.get('username')
    
    # Check if user is admin
    if user_data[username]["role"] != "admin":
        return {"error": "Unauthorized. Admin access required."}, 403
    
    target_user = request.args.get('user')
    if not target_user or target_user not in user_data:
        return {"error": "Invalid user specified"}, 400
    
    # Get the target user's messages
    messages = user_data[target_user].get("messages", [])
    
    # For each message, verify signature
    processed_messages = []
    
    # Create a seen set to track message ids and avoid duplication
    seen_timestamps = set()
    
    for msg in messages:
        # Skip duplicate messages
        msg_timestamp_str = msg["timestamp"].strftime('%Y-%m-%d %H:%M:%S')
        msg_identifier = f"{msg_timestamp_str}_{msg.get('text', '')}"
        
        if msg_identifier in seen_timestamps:
            continue
            
        seen_timestamps.add(msg_identifier)
        
        # Determine the real sender and recipient
        message_type = msg.get("type", "unknown")
        
        if message_type == "outgoing":
            # This is a message sent by the target user
            actual_sender = target_user
            actual_recipient = msg.get("recipient", "unknown")
        elif message_type == "incoming":
            # This is a message received by the target user
            actual_sender = msg.get("sender", "unknown")
            actual_recipient = target_user
        else:
            # Default case, use the values from the message
            actual_sender = msg.get("sender", target_user)
            actual_recipient = msg.get("recipient", "unknown")
        
        # Admin may not have the private key to properly decrypt all messages
        # We're showing the plaintext here for demonstration
        processed_messages.append({
            "text": msg["text"],
            "timestamp": msg_timestamp_str,
            "sender": actual_sender,
            "recipient": actual_recipient,
            "type": message_type
        })
    
    # Sort messages by timestamp (newest first)
    processed_messages.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return {"messages": processed_messages, "user": target_user}, 200

@app.route('/admin/send_message', methods=['POST'])
def admin_send_message():
    if not session.get('logged_in'):
        return {"error": "Unauthorized"}, 401
    
    admin_username = session.get('username')
    
    # Check if user is admin
    if user_data[admin_username]["role"] != "admin":
        return {"error": "Unauthorized. Admin access required."}, 403
    
    target_user = request.form.get('target_user')
    message_text = request.form.get('message')
    
    if not target_user or target_user not in user_data:
        return {"error": "Invalid target user"}, 400
    
    if not message_text:
        return {"error": "Message cannot be empty"}, 400
    
    # Get admin's keys for signing
    admin_private_key = user_data[admin_username]["keys"]["private_key"]
    
    # Get target user's keys for encryption
    if not user_data[target_user]["keys"]:
        return {"error": "Target user has no encryption keys yet"}, 400
    
    target_public_key = user_data[target_user]["keys"]["public_key"]
    
    # Encrypt message with target's public key and sign with admin's private key
    encrypted_message = encrypt_message(message_text, target_public_key)
    signature = sign_message(message_text, admin_private_key)
    
    # Create message timestamp once to keep it consistent
    message_timestamp = datetime.now()
    
    # Store the message in target user's data (as an incoming message)
    if "messages" not in user_data[target_user]:
        user_data[target_user]["messages"] = []
    
    message_data = {
        "text": message_text,
        "encrypted": encrypted_message,
        "signature": signature,
        "timestamp": message_timestamp,
        "sender": admin_username,  # Mark message as from admin
        "type": "incoming"         # Mark as incoming to avoid duplication
    }
    
    user_data[target_user]["messages"].append(message_data)
    
    # Also store a copy of this message in the admin's messages for bidirectional conversation tracking
    if "messages" not in user_data[admin_username]:
        user_data[admin_username]["messages"] = []
    
    # Add a copy to admin's messages to show in admin dashboard (as an outgoing message)
    user_data[admin_username]["messages"].append({
        "text": message_text,
        "encrypted": encrypted_message,
        "signature": signature,
        "timestamp": message_timestamp,
        "sender": admin_username,
        "recipient": target_user,  # Add recipient info for admin's records
        "type": "outgoing"         # Mark as outgoing to avoid duplication
    })
    
    return {"success": True, "message": f"Message sent securely to {target_user}"}, 200

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been successfully logged out", "success")
    return redirect(url_for('login'))

@app.context_processor
def utility_processor():
    def format_time(timestamp):
        if isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(timestamp, datetime):
            return timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return str(timestamp)
    
    return dict(format_time=format_time)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('login.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('login.html'), 500