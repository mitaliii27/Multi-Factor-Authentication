import re
import random
import logging
from datetime import datetime, timedelta
from flask_mail import Message
from flask import flash

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def authenticate_user(user_data, username, password):
    """Authenticate a user by username and password"""
    # Check if account is locked
    if is_account_locked(user_data, username):
        return "locked"
    
    # Verify username and password
    if username in user_data and user_data[username]["password"] == password:
        logger.debug(f"Authentication successful for user {username}")
        return "success"
    else:
        # Increment login attempts
        if username in user_data:
            user_data[username]["login_attempts"] += 1
            
            # Check if account should be locked (3 failed attempts)
            if user_data[username]["login_attempts"] >= 3:
                lock_account(user_data, username)
                return "locked"
        
        logger.debug(f"Authentication failed for user {username}")
        return "failure"

def is_account_locked(user_data, username):
    """Check if the account is locked"""
    if username in user_data and user_data[username]["locked_until"]:
        current_time = datetime.now()
        
        if current_time < user_data[username]["locked_until"]:
            # Account is still locked
            return True
        else:
            # Lock period expired, reset
            user_data[username]["locked_until"] = None
            user_data[username]["login_attempts"] = 0
            return False
    
    return False

def lock_account(user_data, username):
    """Lock an account for 1 hour"""
    lock_until = datetime.now() + timedelta(hours=1)
    user_data[username]["locked_until"] = lock_until
    logger.warning(f"Account {username} locked until {lock_until}")
    return lock_until

def check_panic_password(user_data, username, password):
    """Check if the provided password is the panic password"""
    if username in user_data and user_data[username]["panic_password"] == password:
        logger.warning(f"Panic password used for {username}")
        return True
    return False

def generate_totp():
    """Generate a 6-digit TOTP code"""
    return str(random.randint(100000, 999999))

def send_totp(mail, email):
    """Generate TOTP and send it to user's email"""
    totp_code = generate_totp()
    
    msg = Message(
        subject="Your Secure Authentication Code",
        recipients=[email],
        body=f"Your secure authentication code is: {totp_code}\n\nThis code is valid for 5 minutes."
    )
    
    mail.send(msg)
    logger.info(f"TOTP sent to {email}")
    
    return totp_code

def verify_totp(expected_totp, provided_totp, expiry_timestamp):
    """Verify the TOTP code"""
    # Check if TOTP has expired
    current_time = datetime.now().timestamp()
    if expiry_timestamp and current_time > expiry_timestamp:
        logger.warning("TOTP verification failed: Code expired")
        return False
    
    # Check if TOTP matches
    if expected_totp and provided_totp and expected_totp == provided_totp:
        logger.info("TOTP verification successful")
        return True
    
    logger.warning("TOTP verification failed: Invalid code")
    return False