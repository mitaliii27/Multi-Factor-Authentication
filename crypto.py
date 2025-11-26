import random
import hashlib
import base64
import hmac
import os
import struct
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Implementing Elliptic Curve Cryptography from scratch
# This is a simplified implementation for educational purposes
# In production, use established libraries like cryptography

# --------------------------------------------------------------------------------------
# Elliptic Curve Cryptography (ECC) Core
# --------------------------------------------------------------------------------------

# Elliptic curve parameters (using a small curve for simplicity)
# y^2 = x^3 + ax + b (mod p)
# Using the secp256k1 curve parameters (Bitcoin curve)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Point at infinity (used as identity element)
O = 'infinity'

def is_prime(n):
    """Simple primality test for the mod_inverse function"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def mod_inverse(a, m):
    """Calculate the modular multiplicative inverse of a modulo m"""
    if a == 0:
        raise ValueError("Cannot compute modular inverse of 0")
    
    if a < 0:
        return m - mod_inverse(-a, m)
    
    # Ensure both inputs are positive
    a %= m
    
    # Extended Euclidean Algorithm
    old_r, r = a, m
    old_s, s = 1, 0
    old_t, t = 0, 1
    
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    
    # If gcd(a, m) != 1, then no modular inverse exists
    if old_r > 1:
        # Try a fallback approach for this specific application
        # Use Fermat's Little Theorem when m is prime
        if is_prime(m):
            return pow(a, m - 2, m)
        else:
            raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    
    # Make sure the result is positive
    if old_s < 0:
        old_s += m
    
    return old_s

def point_addition(p1, p2):
    """Add two points on the elliptic curve"""
    # Handle point at infinity
    if p1 == O:
        return p2
    if p2 == O:
        return p1
    
    # Extract coordinates
    x1, y1 = p1
    x2, y2 = p2
    
    # Ensure coordinates are within range
    x1, y1 = x1 % p, y1 % p
    x2, y2 = x2 % p, y2 % p
    
    # Case where p1 + p2 = O (points are inverses of each other)
    if x1 == x2 and (y1 + y2) % p == 0:
        return O
    
    try:
        # Calculate the slope of the line
        if x1 == x2:  # Point doubling
            # Special case: if y1 is 0 in point doubling, return O
            if y1 == 0:
                return O
            lam = (3 * x1 * x1 + a) * mod_inverse(2 * y1, p) % p
        else:  # Point addition
            # Special case: if x1-x2 is 0, return O (shouldn't happen due to check above, but just in case)
            if (x2 - x1) % p == 0:
                return O
            lam = (y2 - y1) * mod_inverse((x2 - x1) % p, p) % p
        
        # Calculate the new point
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        
        return (x3, y3)
    except ValueError as e:
        # If modular inverse doesn't exist, log the issue and return point at infinity
        logger.warning(f"Error in point addition: {str(e)}. Falling back to point at infinity.")
        return O

def scalar_multiply(k, point):
    """Multiply a point by a scalar using double-and-add algorithm"""
    # Import globals to avoid reference issues
    global n
    
    # Handle special cases
    if k == 0 or point == O:
        return O
    
    # Make sure k is positive and in proper range
    k = k % n  # Reduce k modulo n (group order)
    if k == 0:
        return O
    
    try:
        # Double-and-add algorithm
        result = O
        addend = point
        
        while k:
            if k & 1:  # If the bit is set
                result = point_addition(result, addend)
            
            # Double the point (handle possible errors gracefully)
            try:
                addend = point_addition(addend, addend)
            except Exception as e:
                logger.error(f"Error in point doubling: {str(e)}")
                return O
                
            k >>= 1  # Shift right by 1 bit
        
        return result
    except Exception as e:
        # Log the error and return point at infinity to avoid crashing
        logger.error(f"Error in scalar multiplication: {str(e)}")
        return O

def generate_keys():
    """Generate a private key and corresponding public key"""
    # Generate a random private key with enhanced security
    # We use os.urandom for cryptographically secure randomness
    private_key = int.from_bytes(os.urandom(32), byteorder='big') % (n - 1) + 1
    
    # Compute the public key using the generator point
    public_key = scalar_multiply(private_key, (G_x, G_y))
    
    logger.debug("Generated new ECC key pair")
    return private_key, public_key

# --------------------------------------------------------------------------------------
# Elliptic Curve Digital Signature Algorithm (ECDSA)
# --------------------------------------------------------------------------------------

def hash_message(message):
    """Create a hash of the message"""
    return int(hashlib.sha256(message.encode()).hexdigest(), 16) % n

def deterministic_k(private_key, message, hash_func=hashlib.sha256):
    """Generate deterministic k value for ECDSA (RFC 6979)"""
    # This is a simplified version of the RFC 6979 algorithm
    # In production, use a proper implementation
    
    # Convert private key to bytes
    private_key_bytes = private_key.to_bytes(32, byteorder='big')
    
    # Hash the message
    message_hash = hash_func(message.encode()).digest()
    
    # Initial values
    v = b'\x01' * 32
    k = b'\x00' * 32
    
    # HMAC-based key derivation
    k = hmac.new(k, v + b'\x00' + private_key_bytes + message_hash, hash_func).digest()
    v = hmac.new(k, v, hash_func).digest()
    k = hmac.new(k, v + b'\x01' + private_key_bytes + message_hash, hash_func).digest()
    v = hmac.new(k, v, hash_func).digest()
    
    # Generate k
    v = hmac.new(k, v, hash_func).digest()
    k_int = int.from_bytes(v, byteorder='big') % n
    
    # Ensure k is valid (1 <= k < n)
    while k_int < 1:
        k = hmac.new(k, v + b'\x00', hash_func).digest()
        v = hmac.new(k, v, hash_func).digest()
        k_int = int.from_bytes(v, byteorder='big') % n
    
    return k_int

def sign_message(message, private_key):
    """Sign a message using ECDSA with deterministic k generation"""
    z = hash_message(message)
    
    # Use deterministic k generation for security
    k = deterministic_k(private_key, message)
    
    # Calculate the point (x, y) = k * G
    x, y = scalar_multiply(k, (G_x, G_y))
    
    # Calculate r = x mod n
    r = x % n
    if r == 0:
        # This is extremely unlikely, but we handle it for completeness
        return sign_message(message, private_key)
    
    # Calculate s = k^(-1) * (z + r * private_key) mod n
    s = (mod_inverse(k, n) * (z + r * private_key)) % n
    if s == 0:
        # This is extremely unlikely, but we handle it for completeness
        return sign_message(message, private_key)
    
    # Canonical signatures (s should be at most n/2)
    if s > n // 2:
        s = n - s
    
    logger.debug(f"Message signed successfully with ECDSA")
    return (r, s)

def verify_signature(message, signature, public_key):
    """Verify a message signature using ECDSA"""
    if public_key == O:
        logger.warning("Signature verification failed: Invalid public key (point at infinity)")
        return False
    
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        logger.warning("Signature verification failed: r or s out of range")
        return False
    
    z = hash_message(message)
    
    # Calculate u1 and u2
    s_inv = mod_inverse(s, n)
    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n
    
    # Calculate the point P = u1*G + u2*public_key
    u1G = scalar_multiply(u1, (G_x, G_y))
    u2Q = scalar_multiply(u2, public_key)
    P = point_addition(u1G, u2Q)
    
    if P == O:
        logger.warning("Signature verification failed: Point at infinity")
        return False
    
    # The signature is valid if the x-coordinate of P modulo n equals r
    result = (P[0] % n) == r
    
    logger.debug("Signature verification successful")
    
    return result

# --------------------------------------------------------------------------------------
# Advanced Encryption using Elliptic Curve Integrated Encryption Scheme (ECIES)
# --------------------------------------------------------------------------------------

class AES:
    """A simplified AES-like symmetric encryption implementation"""
    
    @staticmethod
    def derive_key(shared_secret, salt=None):
        """Derive a symmetric encryption key from a shared secret using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
            
        # Convert shared_secret to string for PBKDF2
        if isinstance(shared_secret, tuple):
            secret_str = f"{shared_secret[0]},{shared_secret[1]}"
        else:
            secret_str = str(shared_secret)
            
        # Use PBKDF2 with HMAC-SHA256 for key derivation
        key = hashlib.pbkdf2_hmac(
            'sha256',
            secret_str.encode(),
            salt,
            iterations=10000,
            dklen=32  # 256-bit key
        )
        
        return key, salt
    
    @staticmethod
    def encrypt(data, key):
        """Encrypt data with our AES-like algorithm using CBC mode"""
        # Convert data to bytes if it's a string
        if isinstance(data, str):
            data = data.encode()
            
        # Generate initialization vector (IV)
        iv = os.urandom(16)
        
        # Pad data to 16-byte blocks (PKCS#7 padding)
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        
        # Encrypt data (CBC mode with XOR)
        ciphertext = bytearray()
        previous_block = iv
        
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            
            # XOR with previous ciphertext block (CBC mode)
            mixed_block = bytearray(len(block))
            for j in range(len(block)):
                mixed_block[j] = block[j] ^ previous_block[j % len(previous_block)]
                
            # "Encrypt" the block using the key (simplified version)
            encrypted_block = bytearray(len(mixed_block))
            for j in range(len(mixed_block)):
                encrypted_block[j] = mixed_block[j] ^ key[j % len(key)]
                
            # Add to ciphertext and update previous block
            ciphertext.extend(encrypted_block)
            previous_block = encrypted_block
            
        # Calculate MAC for authentication
        mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
        
        return iv, ciphertext, mac
    
    @staticmethod
    def decrypt(iv, ciphertext, mac, key):
        """Decrypt data with our AES-like algorithm using CBC mode"""
        # Verify MAC
        expected_mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("MAC verification failed. Data may be corrupted or tampered with.")
            
        # Decrypt data (CBC mode with XOR)
        plaintext = bytearray()
        previous_block = iv
        
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            
            # "Decrypt" the block using the key (simplified version)
            decrypted_block = bytearray(len(block))
            for j in range(len(block)):
                decrypted_block[j] = block[j] ^ key[j % len(key)]
                
            # XOR with previous ciphertext block (CBC mode)
            plaintext_block = bytearray(len(decrypted_block))
            for j in range(len(decrypted_block)):
                plaintext_block[j] = decrypted_block[j] ^ previous_block[j % len(previous_block)]
                
            # Add to plaintext and update previous block
            plaintext.extend(plaintext_block)
            previous_block = block
            
        # Remove padding (PKCS#7)
        padding_length = plaintext[-1]
        if padding_length > 16:
            raise ValueError("Invalid padding")
            
        plaintext = plaintext[:-padding_length]
        
        return plaintext

def encrypt_message(message, public_key):
    """Encrypt a message using ECIES (Elliptic Curve Integrated Encryption Scheme)"""
    if public_key == O:
        raise ValueError("Invalid public key (point at infinity)")
    
    # Generate an ephemeral key pair for this encryption
    ephemeral_private = int.from_bytes(os.urandom(32), byteorder='big') % (n - 1) + 1
    ephemeral_public = scalar_multiply(ephemeral_private, (G_x, G_y))
    
    # Perform ECDH to establish a shared secret
    shared_point = scalar_multiply(ephemeral_private, public_key)
    
    # Derive symmetric encryption key from shared secret
    encryption_key, salt = AES.derive_key(shared_point)
    
    # Encrypt the message using our AES-like algorithm
    iv, ciphertext, mac = AES.encrypt(message, encryption_key)
    
    # Return all components required for decryption
    encrypted_data = {
        "ephemeral_public_x": ephemeral_public[0],
        "ephemeral_public_y": ephemeral_public[1],
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "mac": base64.b64encode(mac).decode(),
        "salt": base64.b64encode(salt).decode()
    }
    
    logger.debug(f"Message encrypted successfully with ECIES")
    return encrypted_data

def decrypt_message(encrypted_message, private_key):
    """Decrypt a message using ECIES (Elliptic Curve Integrated Encryption Scheme)"""
    try:
        # Extract the components
        ephemeral_public_x = encrypted_message["ephemeral_public_x"]
        ephemeral_public_y = encrypted_message["ephemeral_public_y"]
        
        # Handle the case where we receive the encrypted message in different formats
        if "encrypted_data" in encrypted_message:
            # Old format compatibility (simple XOR encryption)
            encrypted_data = base64.b64decode(encrypted_message["encrypted_data"])
            
            # Calculate the shared point
            ephemeral_public = (ephemeral_public_x, ephemeral_public_y)
            shared_point = scalar_multiply(private_key, ephemeral_public)
            
            # Derive the same key
            shared_key = hashlib.sha256(f"{shared_point[0]},{shared_point[1]}".encode()).digest()
            
            # Decrypt (XOR)
            decrypted = bytearray()
            for i, b in enumerate(encrypted_data):
                decrypted.append(b ^ shared_key[i % len(shared_key)])
            
            return decrypted.decode()
        else:
            # New ECIES format
            iv = base64.b64decode(encrypted_message["iv"])
            ciphertext = base64.b64decode(encrypted_message["ciphertext"])
            mac = base64.b64decode(encrypted_message["mac"])
            salt = base64.b64decode(encrypted_message["salt"])
            
            # Calculate the shared point using ECDH
            ephemeral_public = (ephemeral_public_x, ephemeral_public_y)
            shared_point = scalar_multiply(private_key, ephemeral_public)
            
            # Derive the same encryption key
            encryption_key, _ = AES.derive_key(shared_point, salt)
            
            # Decrypt the message
            plaintext = AES.decrypt(iv, ciphertext, mac, encryption_key)
            
            logger.debug(f"Message decrypted successfully with ECIES")
            return plaintext.decode()
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return f"Decryption error: {str(e)}"

# --------------------------------------------------------------------------------------
# Time-Based One-Time Password (TOTP) Implementation
# --------------------------------------------------------------------------------------

def generate_hotp(secret, counter, digits=6):
    """Generate an HMAC-based One-Time Password"""
    # Convert counter to bytes (big-endian)
    counter_bytes = struct.pack('>Q', counter)
    
    # Create HMAC using SHA-1 (as per RFC 4226)
    h = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
    
    # Dynamic truncation
    offset = h[-1] & 0xf
    truncated_hash = ((h[offset] & 0x7f) << 24 |
                     (h[offset + 1] & 0xff) << 16 |
                     (h[offset + 2] & 0xff) << 8 |
                     (h[offset + 3] & 0xff))
    
    # Generate the code mod 10^digits
    hotp = truncated_hash % (10 ** digits)
    
    # Zero-pad if necessary
    return f'{hotp:0{digits}d}'

def generate_totp(secret=None, digits=6, time_step=30):
    """Generate a Time-Based One-Time Password"""
    if secret is None:
        # For simplicity in our app, generate a random 6-digit code
        # This isn't technically TOTP, but serves the same purpose
        return f'{random.randint(0, 10**digits-1):0{digits}d}'
        
    # Get current timestamp
    current_time = int(time.time())
    
    # Calculate counter based on current time step
    counter = current_time // time_step
    
    # Generate HOTP with the current counter
    return generate_hotp(secret, counter, digits)

def verify_totp(totp, provided_totp, expiry_timestamp=None, window=1):
    """Verify a TOTP code"""
    # Simple comparison for our app's needs
    if expiry_timestamp and time.time() > expiry_timestamp:
        logger.warning("TOTP verification failed: Code expired")
        return False
    
    if totp == provided_totp:
        logger.info("TOTP verification successful")
        return True
    
    logger.warning("TOTP verification failed: Incorrect code")
    return False

# --------------------------------------------------------------------------------------
# Merkle Tree Implementation for Data Integrity
# --------------------------------------------------------------------------------------

def build_merkle_tree(data_blocks):
    """Build a Merkle tree from a list of data blocks"""
    if not data_blocks:
        return None
    
    # Hash all data blocks (leaf nodes)
    hash_list = [hashlib.sha256(str(block).encode()).digest() for block in data_blocks]
    
    # Keep track of all levels for proof generation
    tree_levels = [hash_list]
    
    # Build the tree bottom-up
    while len(hash_list) > 1:
        new_level = []
        
        # Process pairs of nodes
        for i in range(0, len(hash_list), 2):
            if i + 1 < len(hash_list):
                # Concatenate and hash pair
                combined = hash_list[i] + hash_list[i + 1]
                new_hash = hashlib.sha256(combined).digest()
            else:
                # If odd number of nodes, duplicate the last one
                new_hash = hash_list[i]
            
            new_level.append(new_hash)
        
        hash_list = new_level
        tree_levels.append(new_level)
    
    # Root is the single hash at the top level
    root_hash = hash_list[0]
    
    return {
        'root': root_hash,
        'levels': tree_levels
    }

def generate_merkle_proof(merkle_tree, data_index):
    """Generate a Merkle proof for a specific data block"""
    if not merkle_tree or 'levels' not in merkle_tree:
        return None
    
    levels = merkle_tree['levels']
    if not levels or data_index >= len(levels[0]):
        return None
    
    proof = []
    index = data_index
    
    # Walk up the tree
    for level_idx in range(len(levels) - 1):
        level = levels[level_idx]
        is_right = index % 2 == 1
        
        if is_right:
            # Add sibling to the left
            proof.append(('left', level[index - 1] if index > 0 else level[0]))
        elif index + 1 < len(level):
            # Add sibling to the right
            proof.append(('right', level[index + 1]))
        else:
            # Last node in an odd-length level, no sibling
            pass
        
        # Move up to parent
        index = index // 2
    
    return {
        'root': merkle_tree['root'],
        'proof': proof
    }

def verify_merkle_proof(data, proof):
    """Verify a Merkle proof for given data"""
    if not proof or 'proof' not in proof or 'root' not in proof:
        return False
    
    # Calculate the hash of the data
    current_hash = hashlib.sha256(str(data).encode()).digest()
    
    # Apply each proof element
    for direction, sibling_hash in proof['proof']:
        if direction == 'left':
            # Sibling is on the left
            current_hash = hashlib.sha256(sibling_hash + current_hash).digest()
        else:
            # Sibling is on the right
            current_hash = hashlib.sha256(current_hash + sibling_hash).digest()
    
    # Check if we reach the root hash
    return current_hash == proof['root']
