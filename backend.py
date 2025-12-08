"""
backend.py

This file contains all the core cryptographic logic, database handling,
and business logic for the secure journaling application. It is designed
to be completely separate from the UI.
"""
import json
import os
import hashlib
import base64
import re
from datetime import datetime, timezone, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# New imports for PKI
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Constants ---
USER_DB = 'users.json'
ENTRIES_DB = 'entries.json'
SHARES_DB = 'shares.json'
ROOT_CA_KEY = 'root_ca.pem'
ROOT_CA_CERT = 'root_ca.crt'
# Strong passphrase for Root CA private key protection
CA_PASSPHRASE = b'SecureJournal_RootCA_2025_ProtectedKey!@#'

ph = PasswordHasher()
ROOT_CA_PUBLIC_CERT = None # Cache for the root CA cert

# --- Database Handling ---
def load_users():
    """Loads the user database from the JSON file."""
    if not os.path.exists(USER_DB):
        return {}
    with open(USER_DB, 'r') as f:
        try:
            return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

def save_users(users):
    """Saves the user database to the JSON file."""
    with open(USER_DB, 'w') as f:
        json.dump(users, f, indent=4)

def load_entries():
    """Loads the journal entries from the JSON file."""
    if not os.path.exists(ENTRIES_DB):
        return {}
    with open(ENTRIES_DB, 'r') as f:
        try:
            return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

def save_entries(entries):
    """Saves the journal entries to the JSON file."""
    with open(ENTRIES_DB, 'w') as f:
        json.dump(entries, f, indent=4)

def load_shares():
    """Loads the shares from the JSON file, ensuring a list is returned."""
    if not os.path.exists(SHARES_DB):
        return []
    with open(SHARES_DB, 'r') as f:
        try:
            data = json.load(f)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, FileNotFoundError):
            return []

def save_shares(shares):
    """Saves the shares to the JSON file."""
    with open(SHARES_DB, 'w') as f:
        json.dump(shares, f, indent=4)

# --- PKI and Certificate Authority Logic ---
def setup_root_ca():
    """
    Checks for the Root CA key and certificate. If they don't exist,
    it generates them. This function establishes our root of trust.
    Returns a status message.
    """
    global ROOT_CA_PUBLIC_CERT
    # Only generate if files don't exist
    if not os.path.exists(ROOT_CA_KEY) or not os.path.exists(ROOT_CA_CERT):
        # ... (generation logic as before)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        # Encrypt the Root CA private key with a strong passphrase
        with open(ROOT_CA_KEY, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(CA_PASSPHRASE)
            ))

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureJournal CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"securejournal.ca"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256(), default_backend())

        with open(ROOT_CA_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        status_msg = "Root CA generated successfully."
    else:
        status_msg = "Root CA already exists."

    # Load the Root CA public cert into memory for verification tasks
    with open(ROOT_CA_CERT, 'rb') as f:
        ROOT_CA_PUBLIC_CERT = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return status_msg

def verify_user_cert(username):
    # ... (function is largely the same, returns public key or None)
    global ROOT_CA_PUBLIC_CERT
    if not ROOT_CA_PUBLIC_CERT:
        return None
        
    users = load_users()
    user_data = users.get(username)
    if not user_data or 'user_certificate' not in user_data:
        return None
    
    try:
        user_cert_pem = user_data['user_certificate'].encode('utf-8')
        user_cert = x509.load_pem_x509_certificate(user_cert_pem, default_backend())
        
        ca_public_key = ROOT_CA_PUBLIC_CERT.public_key()
        
        ca_public_key.verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), 
            user_cert.signature_hash_algorithm,
        )
        
        now = datetime.now(timezone.utc)
        if not (user_cert.not_valid_before_utc <= now <= user_cert.not_valid_after_utc):
             return None
             
        return RSA.import_key(user_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    except Exception:
        return None

# --- Password Validation ---

def validate_password(password):
    """
    Validates password strength requirements:
    - Minimum 8 characters
    - At least one number
    - At least one special character
    
    Returns (bool, error_message).
    """
    if len(password) < 8:
        return (False, "Password must be at least 8 characters long.")
    
    if not re.search(r'\d', password):
        return (False, "Password must contain at least one number.")
    
    # Check for special characters (any non-alphanumeric, non-space character)
    if not re.search(r'[^a-zA-Z0-9\s]', password):
        return (False, "Password must contain at least one special character (e.g., !@#$%^&*(),.?\":{}|<>).")
    
    return (True, "")

# --- Core Logic Functions ---

def register_user(username, password):
    """
    Handles new user registration.
    Returns (bool, message).
    """
    users = load_users()
    if username in users:
        return (False, "Username already exists. Please choose another one.")
    
    # Validate password strength
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return (False, error_msg)
    
    try:
        hash_with_salt = ph.hash(password)
        user_key_obj = RSA.generate(2048)

        # Load the encrypted Root CA private key
        with open(ROOT_CA_KEY, 'rb') as f:
            ca_priv_key = serialization.load_pem_private_key(f.read(), password=CA_PASSPHRASE, backend=default_backend())

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"user_{username}")])
        user_public_key_for_cert = user_key_obj.publickey()
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ROOT_CA_PUBLIC_CERT.subject
        ).public_key(
            serialization.load_pem_public_key(
                user_public_key_for_cert.export_key(), backend=default_backend()
            )
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        
        user_cert = builder.sign(ca_priv_key, hashes.SHA256(), default_backend())

        encrypted_private_key = user_key_obj.export_key(
            passphrase=password, pkcs=8, protection="scryptAndAES128-CBC"
        ).decode('utf-8')

        users[username] = {
            "hash": hash_with_salt,
            "user_certificate": user_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            "encrypted_private_key": encrypted_private_key
        }
        save_users(users)
        return (True, f"User '{username}' registered and certificate issued successfully!")
        
    except Exception as e:
        return (False, f"An error occurred during registration: {e}")

def login_user(username, password):
    """
    Handles user login.
    Returns (bool, master_key, signing_key, message).
    """
    users = load_users()
    if username not in users:
        return (False, None, None, "Login failed: User not found.")

    user_data = users[username]
    stored_hash = user_data['hash']

    try:
        ph.verify(stored_hash, password)
        
        parts = stored_hash.split('$')
        salt_b64 = parts[4]
        salt_b64 += '=' * (-len(salt_b64) % 4)
        salt = base64.b64decode(salt_b64)
        
        password_bytes = password.encode('utf-8')
        master_key = hashlib.pbkdf2_hmac(
            'sha256', password_bytes, salt, 600000, dklen=32
        )
        
        encrypted_priv_key_pem = user_data['encrypted_private_key']
        signing_key = RSA.import_key(encrypted_priv_key_pem, passphrase=password)
        
        return (True, master_key, signing_key, "Login successful.")

    except (VerifyMismatchError, ValueError):
        return (False, None, None, "Login failed: Incorrect password or corrupted key.")
    except Exception as e:
        return (False, None, None, f"An error occurred during login: {e}")

def change_password(username, current_password, new_password):
    """
    Handles password change for a user.
    Requires current password verification and re-encrypts the private key.
    Also re-encrypts all DEKs (Data Encryption Keys) for user's entries since
    the master key is derived from the password.
    Returns (bool, message).
    """
    users = load_users()
    if username not in users:
        return (False, "User not found.")
    
    user_data = users[username]
    stored_hash = user_data['hash']
    
    # Verify current password
    try:
        ph.verify(stored_hash, current_password)
    except VerifyMismatchError:
        return (False, "Current password is incorrect.")
    
    # Validate new password strength
    is_valid, error_msg = validate_password(new_password)
    if not is_valid:
        return (False, error_msg)
    
    try:
        # Derive old master key from current password (using salt from old hash)
        parts = stored_hash.split('$')
        old_salt_b64 = parts[4]
        old_salt_b64 += '=' * (-len(old_salt_b64) % 4)
        old_salt = base64.b64decode(old_salt_b64)
        old_master_key = hashlib.pbkdf2_hmac(
            'sha256', current_password.encode('utf-8'), old_salt, 600000, dklen=32
        )
        
        # Decrypt the private key with old password
        encrypted_priv_key_pem = user_data['encrypted_private_key']
        signing_key = RSA.import_key(encrypted_priv_key_pem, passphrase=current_password)
        
        # Generate new password hash (this will have a new salt)
        new_hash = ph.hash(new_password)
        
        # Extract salt from new hash and derive new master key
        new_parts = new_hash.split('$')
        new_salt_b64 = new_parts[4]
        new_salt_b64 += '=' * (-len(new_salt_b64) % 4)
        new_salt = base64.b64decode(new_salt_b64)
        new_master_key = hashlib.pbkdf2_hmac(
            'sha256', new_password.encode('utf-8'), new_salt, 600000, dklen=32
        )
        
        # Re-encrypt the private key with new password
        new_encrypted_private_key = signing_key.export_key(
            passphrase=new_password, pkcs=8, protection="scryptAndAES128-CBC"
        ).decode('utf-8')
        
        # Re-encrypt all DEKs for user's entries
        entries = load_entries()
        user_entries = entries.get(username, {})
        entries_updated = 0
        
        for entry_id, entry_data in user_entries.items():
            try:
                # Decrypt DEK with old master key
                nonce_dek = bytes.fromhex(entry_data['nonce_dek'])
                tag_dek = bytes.fromhex(entry_data['tag_dek'])
                ciphertext_dek = bytes.fromhex(entry_data['encrypted_dek'])
                cipher_dek_old = AES.new(old_master_key, AES.MODE_GCM, nonce=nonce_dek)
                dek = cipher_dek_old.decrypt_and_verify(ciphertext_dek, tag_dek)
                
                # Re-encrypt DEK with new master key
                new_nonce_dek = get_random_bytes(12)
                cipher_dek_new = AES.new(new_master_key, AES.MODE_GCM, nonce=new_nonce_dek)
                new_ciphertext_dek, new_tag_dek = cipher_dek_new.encrypt_and_digest(dek)
                
                # Update entry with new encrypted DEK
                entry_data['encrypted_dek'] = new_ciphertext_dek.hex()
                entry_data['nonce_dek'] = new_nonce_dek.hex()
                entry_data['tag_dek'] = new_tag_dek.hex()
                entries_updated += 1
            except Exception:
                # If we can't decrypt an entry, skip it (might be corrupted)
                continue
        
        # Save updated entries
        if entries_updated > 0:
            save_entries(entries)
        
        # Update user data
        users[username]['hash'] = new_hash
        users[username]['encrypted_private_key'] = new_encrypted_private_key
        save_users(users)
        
        return (True, f"Password changed successfully! {entries_updated} journal entries updated. Please log in again with your new password.")
        
    except Exception as e:
        return (False, f"An error occurred while changing password: {e}")

def change_username(old_username, password, new_username):
    """
    Handles username change for a user.
    This is a complex operation that updates all references to the user across the system.
    Returns (bool, message).
    """
    users = load_users()
    
    # Verify user exists and password is correct
    if old_username not in users:
        return (False, "User not found.")
    
    if new_username in users:
        return (False, "New username already exists. Please choose another one.")
    
    user_data = users[old_username]
    stored_hash = user_data['hash']
    
    # Verify password
    try:
        ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return (False, "Password is incorrect.")
    
    try:
        # Decrypt private key to get the key object
        encrypted_priv_key_pem = user_data['encrypted_private_key']
        user_key_obj = RSA.import_key(encrypted_priv_key_pem, passphrase=password)
        
        # Load encrypted Root CA key for re-issuing certificate
        with open(ROOT_CA_KEY, 'rb') as f:
            ca_priv_key = serialization.load_pem_private_key(f.read(), password=CA_PASSPHRASE, backend=default_backend())
        
        # Generate new certificate with new username
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"user_{new_username}")])
        user_public_key_for_cert = user_key_obj.publickey()
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ROOT_CA_PUBLIC_CERT.subject
        ).public_key(
            serialization.load_pem_public_key(
                user_public_key_for_cert.export_key(), backend=default_backend()
            )
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        
        new_user_cert = builder.sign(ca_priv_key, hashes.SHA256(), default_backend())
        
        # Create new user entry
        users[new_username] = {
            "hash": user_data['hash'],
            "user_certificate": new_user_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            "encrypted_private_key": user_data['encrypted_private_key']  # Same key, same password
        }
        
        # Delete old user entry
        del users[old_username]
        save_users(users)
        
        # Update entries.json - move all entries from old username to new
        entries = load_entries()
        if old_username in entries:
            entries[new_username] = entries[old_username]
            del entries[old_username]
            save_entries(entries)
        
        # Update shares.json - update owner and recipient fields
        shares = load_shares()
        for share in shares:
            if share.get('entry_owner') == old_username:
                share['entry_owner'] = new_username
            if share.get('recipient') == old_username:
                share['recipient'] = new_username
        save_shares(shares)
        
        return (True, f"Username changed from '{old_username}' to '{new_username}' successfully! Please log in again with your new username.")
        
    except Exception as e:
        return (False, f"An error occurred while changing username: {e}")

def write_new_entry(username, master_key, signing_key, plaintext):
    """
    Handles writing a new, encrypted journal entry.
    Returns (bool, message).
    """
    try:
        dek = get_random_bytes(32)
        nonce_msg = get_random_bytes(12)
        cipher_msg = AES.new(dek, AES.MODE_GCM, nonce=nonce_msg)
        ciphertext_msg, tag_msg = cipher_msg.encrypt_and_digest(plaintext.encode('utf-8'))

        nonce_dek = get_random_bytes(12)
        cipher_dek = AES.new(master_key, AES.MODE_GCM, nonce=nonce_dek)
        ciphertext_dek, tag_dek = cipher_dek.encrypt_and_digest(dek)
        
        entry_id = datetime.now(timezone.utc).isoformat()
        
        # Sign all entry data to ensure complete integrity protection
        data_to_sign = (entry_id.encode('utf-8') + 
                       nonce_msg + tag_msg + ciphertext_msg + 
                       nonce_dek + tag_dek + ciphertext_dek)
        h = SHA256.new(data_to_sign)
        signer = pss.new(signing_key)
        signature = signer.sign(h)
        entries = load_entries()
        
        if username not in entries:
            entries[username] = {}
            
        entries[username][entry_id] = {
            "encrypted_message": ciphertext_msg.hex(),
            "nonce_msg": nonce_msg.hex(),
            "tag_msg": tag_msg.hex(),
            "encrypted_dek": ciphertext_dek.hex(),
            "nonce_dek": nonce_dek.hex(),
            "tag_dek": tag_dek.hex(),
            "signature": signature.hex()
        }
        
        save_entries(entries)
        return (True, "Journal entry saved and signed successfully!")

    except Exception as e:
        return (False, f"An error occurred while writing the entry: {e}")

def read_user_entries(username):
    """
    Handles reading and decrypting all entries for the current user.
    Returns a list of dictionaries, each representing an entry.
    """
    public_key = verify_user_cert(username)
    if not public_key:
        return [{"id": "Error", "message": "Cannot read entries: your certificate is invalid.", "verified": False}]
        
    verifier = pss.new(public_key)
    entries = load_entries()
    user_entries = entries.get(username, {})

    if not user_entries:
        return []

    sorted_entries = sorted(user_entries.items())
    results = []

    for entry_id, entry_data in sorted_entries:
        entry_result = {"id": entry_id, "message": "", "verified": False}
        try:
            signature = bytes.fromhex(entry_data['signature'])
            nonce_msg_bytes = bytes.fromhex(entry_data['nonce_msg'])
            tag_msg_bytes = bytes.fromhex(entry_data['tag_msg'])
            ciphertext_msg_bytes = bytes.fromhex(entry_data['encrypted_message'])
            nonce_dek_bytes = bytes.fromhex(entry_data['nonce_dek'])
            tag_dek_bytes = bytes.fromhex(entry_data['tag_dek'])
            ciphertext_dek_bytes = bytes.fromhex(entry_data['encrypted_dek'])
            
            # Verify signature over all entry data
            data_to_verify = (entry_id.encode('utf-8') + 
                            nonce_msg_bytes + tag_msg_bytes + ciphertext_msg_bytes + 
                            nonce_dek_bytes + tag_dek_bytes + ciphertext_dek_bytes)
            h = SHA256.new(data_to_verify)
            
            verifier.verify(h, signature)
            entry_result["verified"] = True
            
            # To read an entry, you need the master key, which is not available here.
            # This function will only verify. Decryption must happen in the UI layer
            # where the key is held in session state.
            # We will return the raw data needed for decryption.
            entry_result["data"] = entry_data

        except (ValueError, TypeError):
            entry_result["message"] = "TAMPERING DETECTED! Signature verification failed."
        except Exception as e:
            entry_result["message"] = f"Could not process entry. It may be corrupt. Details: {e}"
        results.append(entry_result)
    return results

def decrypt_entry_data(master_key, entry_data):
    """
    Helper function to decrypt the message from raw entry data.
    """
    try:
        # Decrypt DEK
        nonce_dek = bytes.fromhex(entry_data['nonce_dek'])
        tag_dek = bytes.fromhex(entry_data['tag_dek'])
        ciphertext_dek = bytes.fromhex(entry_data['encrypted_dek'])
        cipher_dek = AES.new(master_key, AES.MODE_GCM, nonce=nonce_dek)
        dek = cipher_dek.decrypt_and_verify(ciphertext_dek, tag_dek)

        # Decrypt Message
        nonce_msg = bytes.fromhex(entry_data['nonce_msg'])
        tag_msg = bytes.fromhex(entry_data['tag_msg'])
        ciphertext_msg = bytes.fromhex(entry_data['encrypted_message'])
        cipher_msg = AES.new(dek, AES.MODE_GCM, nonce=nonce_msg)
        plaintext = cipher_msg.decrypt_and_verify(ciphertext_msg, tag_msg)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption Failed: {e}"


def share_entry(owner_username, master_key, recipient_username, entry_id):
    """
    Securely shares a journal entry with another user.
    Returns (bool, message).
    """
    if recipient_username == owner_username:
        return (False, "You cannot share an entry with yourself.")

    recipient_pub_key = verify_user_cert(recipient_username)
    if not recipient_pub_key:
        return (False, f"Could not share: recipient '{recipient_username}' has no valid certificate.")

    try:
        entries = load_entries()
        entry_data = entries.get(owner_username, {}).get(entry_id)
        if not entry_data:
            return (False, f"Error: Entry ID '{entry_id}' not found in your journal.")

        # Decrypt the DEK
        dek = decrypt_entry_data(master_key, {"nonce_dek": entry_data['nonce_dek'], "tag_dek": entry_data['tag_dek'], "encrypted_dek": entry_data['encrypted_dek']})
        if isinstance(dek, str) and dek.startswith("Decryption Failed"):
             # A bit of a hack, but decrypt_entry_data returns string on error
             # A better way would be to split decrypt_dek and decrypt_message
             nonce_dek = bytes.fromhex(entry_data['nonce_dek'])
             tag_dek = bytes.fromhex(entry_data['tag_dek'])
             ciphertext_dek = bytes.fromhex(entry_data['encrypted_dek'])
             cipher_dek = AES.new(master_key, AES.MODE_GCM, nonce=nonce_dek)
             dek = cipher_dek.decrypt_and_verify(ciphertext_dek, tag_dek)


        # Re-encrypt the DEK for the recipient
        cipher_rsa = PKCS1_OAEP.new(recipient_pub_key)
        encrypted_dek_for_recipient = cipher_rsa.encrypt(dek)

        shares = load_shares()
        shares.append({
            "entry_owner": owner_username,
            "recipient": recipient_username,
            "entry_id": entry_id,
            "encrypted_dek": encrypted_dek_for_recipient.hex()
        })
        save_shares(shares)
        
        return (True, f"Successfully shared entry '{entry_id}' with '{recipient_username}'.")

    except Exception as e:
        return (False, f"An error occurred during the sharing process: {e}")

def view_shared_entries(username, signing_key):
    """
    Views entries that have been shared with the current user.
    Returns a list of dictionaries.
    """
    shares = load_shares()
    my_shares = [s for s in shares if s.get('recipient') == username]

    if not my_shares:
        return []

    entries = load_entries()
    cipher_rsa = PKCS1_OAEP.new(signing_key)
    results = []

    for share in my_shares:
        entry_id = share['entry_id']
        owner = share['entry_owner']
        result = {"id": entry_id, "owner": owner, "message": ""}
        
        try:
            owner_entries = entries.get(owner, {})
            entry_data = owner_entries.get(entry_id)
            if not entry_data:
                result["message"] = "ERROR: The original entry data could not be found."
                results.append(result)
                continue

            encrypted_dek = bytes.fromhex(share['encrypted_dek'])
            dek = cipher_rsa.decrypt(encrypted_dek)
            
            nonce_msg = bytes.fromhex(entry_data['nonce_msg'])
            tag_msg = bytes.fromhex(entry_data['tag_msg'])
            ciphertext_msg = bytes.fromhex(entry_data['encrypted_message'])
            cipher_msg = AES.new(dek, AES.MODE_GCM, nonce=nonce_msg)
            plaintext = cipher_msg.decrypt_and_verify(ciphertext_msg, tag_msg)
            
            result["message"] = plaintext.decode('utf-8')
        
        except Exception as e:
            result["message"] = f"ERROR: Could not decrypt shared entry. Details: {e}"
        
        results.append(result)
    return results
