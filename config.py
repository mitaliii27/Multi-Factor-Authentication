# Configuration file for the secure crypto application

# Security settings
SESSION_LIFETIME_HOURS = 6
TOTP_LIFETIME_MINUTES = 5
ACCOUNT_LOCKOUT_HOURS = 1
FAILED_LOGIN_LOCKOUT_THRESHOLD = 3

# Default cryptography settings
ECC_CURVE = "secp256k1"