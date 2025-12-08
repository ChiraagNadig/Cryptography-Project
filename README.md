# Cryptography Project - Secure Journal

This is a secure journaling application built for a university cryptography course. The application is a multi-user web application with a comprehensive cryptographic stack implementing authenticated encryption, digital signatures, and a mini-PKI.

## Features

*   **User Authentication**: Secure user registration and login using Argon2 password hashing with strong password requirements (8+ characters, number, special character).
*   **Key Management**: Hierarchical key derivation using PBKDF2-HMAC-SHA256 (600,000 iterations). Master Key derived from password and held only in memory.
*   **Authenticated Encryption**: Journal entries encrypted using per-entry Data Encryption Keys (DEK) with AES-256-GCM. DEKs are wrapped by the user's Master Key.
*   **Digital Signatures**: Each entry is digitally signed with RSA-PSS (SHA-256) to ensure integrity and non-repudiation. Signatures cover all entry data including encrypted content and metadata.
*   **Mini-PKI**: Self-contained Certificate Authority (CA) with encrypted private key. All user signing keys are certified by the Root CA, creating a chain of trust.
*   **Secure Sharing**: Hybrid encryption scheme using RSA-OAEP to securely share symmetric DEKs between users.
*   **Account Management**: Users can change passwords (with automatic key re-encryption) and usernames.

## Architecture

*   **`app.py`**: A Streamlit web application that serves as the frontend. It handles all UI components and user interaction.
*   **`backend.py`**: A separate module containing all core cryptographic logic, business logic, and database interactions. It is completely decoupled from the UI.
*   **`users.json`**: Stores user data, including their password hash and their X.509 certificate.
*   **`entries.json`**: Stores the encrypted journal entries, including ciphertext, nonces, tags, and signatures.
*   **`shares.json`**: Stores records of shared entries, containing the DEK re-encrypted for the recipient.
*   **`root_ca.pem` / `root_ca.crt`**: The private key and self-signed certificate for the application's root Certificate Authority. These are generated automatically on first run.

## How to Run

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Streamlit App:**
    ```bash
    streamlit run app.py
    ```

3.  Open the provided URL in your browser to use the application.

## Cryptographic Design

### Algorithm Selection

**Password Hashing**: Argon2id
- Memory-hard function resistant to GPU/ASIC attacks
- Default parameters: 64MB memory, 3 iterations, 4 parallelism

**Key Derivation**: PBKDF2-HMAC-SHA256
- 600,000 iterations (OWASP recommended minimum)
- Derives 256-bit Master Key from password + Argon2 salt
- Master Key exists only in memory (session state)

**Symmetric Encryption**: AES-256-GCM
- Authenticated encryption with associated data (AEAD)
- 256-bit keys, 96-bit nonces (randomly generated)
- Provides both confidentiality and integrity

**Asymmetric Encryption**: RSA-OAEP (2048-bit)
- Used for secure key sharing between users
- OAEP padding prevents chosen-ciphertext attacks

**Digital Signatures**: RSA-PSS with SHA-256
- Probabilistic signature scheme (PSS) for enhanced security
- 2048-bit RSA keys
- Signatures cover: entry_id + all encrypted data + all nonces/tags

**User Private Key Protection**: Scrypt + AES-128-CBC
- User's RSA private key encrypted with their password
- Scrypt provides additional key stretching

**Root CA Protection**: AES-256-CBC (BestAvailableEncryption)
- Root CA private key encrypted with strong passphrase
- Protects the entire PKI infrastructure

### Key Hierarchy

```
Password (user input)
    ↓
[Argon2] → Password Hash (stored)
    ↓
[PBKDF2 + Argon2 salt] → Master Key (256-bit, memory only)
    ↓
[AES-GCM] → Wraps per-entry DEK
    ↓
DEK (256-bit, random per entry)
    ↓
[AES-GCM] → Encrypts journal entry
```

### Security Properties

**Confidentiality**:
- Journal entries encrypted with unique DEKs
- DEKs wrapped with user-specific Master Keys
- Master Keys never stored on disk
- Forward secrecy: compromising one entry doesn't affect others

**Integrity**:
- AES-GCM provides authenticated encryption
- Digital signatures on all entry data
- Signature verification before displaying entries
- Tampering detection with clear error messages

**Authentication**:
- Argon2 password hashing
- X.509 certificates for all users
- Certificate validation on every signature verification
- Certificate expiry checking

**Non-repudiation**:
- RSA digital signatures prove authorship
- Signatures verified using certified public keys
- PKI provides chain of trust

### Data Protection

**Encrypted Data**:
- Journal entry plaintext
- Data Encryption Keys (DEKs)
- User RSA private keys
- Root CA private key

**Unencrypted Data**:
- Password hashes (Argon2)
- X.509 certificates (public)
- Entry metadata (IDs, timestamps)
- Encrypted ciphertexts, nonces, tags

### Code Examples

**Entry Creation** (`backend.py` lines 494-529):
```python
# Generate unique DEK for this entry
dek = get_random_bytes(32)

# Encrypt message with DEK using AES-GCM
cipher_msg = AES.new(dek, AES.MODE_GCM, nonce=nonce_msg)
ciphertext_msg, tag_msg = cipher_msg.encrypt_and_digest(plaintext)

# Wrap DEK with Master Key
cipher_dek = AES.new(master_key, AES.MODE_GCM, nonce=nonce_dek)
ciphertext_dek, tag_dek = cipher_dek.encrypt_and_digest(dek)

# Sign all entry data
data_to_sign = entry_id + nonce_msg + tag_msg + ciphertext_msg + 
               nonce_dek + tag_dek + ciphertext_dek
signature = signer.sign(SHA256.new(data_to_sign))
```

**Signature Verification** (`backend.py` lines 556-571):
```python
# Verify user's certificate with Root CA
public_key = verify_user_cert(username)

# Reconstruct signed data
data_to_verify = entry_id + nonce_msg + tag_msg + ciphertext_msg + 
                 nonce_dek + tag_dek + ciphertext_dek

# Verify signature
verifier = pss.new(public_key)
verifier.verify(SHA256.new(data_to_verify), signature)
```

**Secure Sharing** (`backend.py` lines 599-645):
```python
# Decrypt DEK with owner's Master Key
dek = decrypt_dek_with_master_key(master_key, encrypted_dek)

# Get recipient's certified public key
recipient_pub_key = verify_user_cert(recipient_username)

# Re-encrypt DEK for recipient using RSA-OAEP
cipher_rsa = PKCS1_OAEP.new(recipient_pub_key)
encrypted_dek_for_recipient = cipher_rsa.encrypt(dek)
```

### Security Assumptions

- Users choose strong passwords (enforced: 8+ chars, number, special char)
- Application runs in trusted environment
- Root CA passphrase is kept secure
- Session state is protected by Streamlit framework
- File system access is restricted to authorized users
- No active attackers during session

### Known Limitations

- No session timeout mechanism
- No rate limiting on login attempts
- No certificate revocation (CRL/OCSP)
- Root CA passphrase hardcoded (acceptable for academic project)
- No key rotation mechanism
- Single-machine deployment only
