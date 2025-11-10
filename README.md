# Cryptography Project - Secure Journal

This is a secure journaling application built as a series of sprints for a university cryptography course. The final version is a multi-user web application with a full cryptographic stack.

## Features

*   **User Authentication**: Secure user registration and login using Argon2 password hashing.
*   **Key Management**: Derives a Master Key from the user's password (PBKDF2) which is held only in memory.
*   **Authenticated Encryption**: Journal entries are encrypted using a per-entry Data Encryption Key (DEK) with AES-GCM. The DEK itself is encrypted (wrapped) by the user's Master Key.
*   **Digital Signatures**: Each entry is digitally signed with the user's unique RSA private key (RSA-PSS with SHA-256) to ensure integrity and non-repudiation.
*   **Mini-PKI**: The application runs its own Certificate Authority (CA). All user signing keys are certified by the CA, creating a chain of trust.
*   **Secure Sharing**: Users can securely share journal entries with other users via a hybrid encryption scheme (RSA-OAEP to share the symmetric DEK).

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
