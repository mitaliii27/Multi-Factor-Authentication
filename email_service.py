import logging
from datetime import datetime
from flask_mail import Message
from threading import Thread

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def send_email_async(mail, message):
    """Send an email asynchronously using Flask-Mail"""
    with mail.app.app_context():
        mail.send(message)

def send_panic_alert(mail, username, timestamp):
    """
    Send an alert email when the panic password is used.
    
    Parameters:
    - mail: Flask-Mail instance
    - username: The username of the account that triggered the panic alert
    - timestamp: The time when the panic password was used
    """
    # Create the message
    msg = Message(
        subject="⚠️ SECURITY ALERT: Panic Password Used",
        recipients=["willycryptoproj@gmail.com"],  # Alert email from app.py
        body=f"""
SECURITY ALERT

A panic password was used for account: {username}
Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}

This may indicate that the user was under duress or coercion.
Appropriate security protocols should be initiated immediately.

- Secure Cryptographic System
"""
    )
    
    # Send asynchronously
    Thread(target=send_email_async, args=(mail, msg)).start()
    logger.warning(f"Panic alert email sent for user {username}")

def send_lock_alert(mail, username, timestamp):
    """
    Send an alert email when an account is locked due to failed login attempts.
    
    Parameters:
    - mail: Flask-Mail instance
    - username: The locked account's username
    - timestamp: The time when the account was locked
    """
    # Create the message
    msg = Message(
        subject="⚠️ SECURITY ALERT: Account Locked",
        recipients=["willycryptoproj@gmail.com"],  # Alert email from app.py
        body=f"""
SECURITY ALERT

Account has been locked due to multiple failed login attempts.

Username: {username}
Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}

The account will remain locked for 1 hour. This may indicate a brute force 
attack attempt or that the user has forgotten their password.

- Secure Cryptographic System
"""
    )
    
    # Send asynchronously
    Thread(target=send_email_async, args=(mail, msg)).start()
    logger.warning(f"Account lock alert email sent for user {username}")