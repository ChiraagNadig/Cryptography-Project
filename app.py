"""
app.py

This is the Streamlit frontend for the Secure Journal application.
It handles all user interface elements and calls the backend for
cryptographic operations.
"""
import streamlit as st
import backend

# --- App Initialization ---
st.set_page_config(page_title="Secure Journal", layout="wide")

# Initialize the Root CA on first run
if 'ca_setup' not in st.session_state:
    st.session_state['ca_setup'] = backend.setup_root_ca()

# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ""
    st.session_state['master_key'] = None
    st.session_state['signing_key'] = None

# --- UI Functions ---

def show_login_page():
    st.title("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            success, master_key, signing_key, message = backend.login_user(username, password)
            if success:
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
                st.session_state['master_key'] = master_key
                st.session_state['signing_key'] = signing_key
                st.rerun()
            else:
                st.error(message)

def show_register_page():
    st.title("Register New User")
    
    # Display password requirements
    st.info("""
    **Password Requirements:**
    - Minimum 8 characters
    - At least one number (0-9)
    - At least one special character (!@#$%^&*(),.?":{}|<>)
    """)
    
    with st.form("register_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password", help="Must be at least 8 characters with a number and special character")
        submitted = st.form_submit_button("Register")

        if submitted:
            if not username:
                st.error("Username is required.")
            elif not password:
                st.error("Password is required.")
            else:
                with st.spinner("Generating keys and certificate... This may take a moment."):
                    success, message = backend.register_user(username, password)
                if success:
                    st.success(message)
                    st.info("You can now log in.")
                else:
                    st.error(message)

def show_write_entry_page():
    st.title("Write a New Journal Entry")
    with st.form("new_entry_form"):
        entry_text = st.text_area("Your entry:")
        submitted = st.form_submit_button("Save and Sign Entry")

        if submitted:
            success, message = backend.write_new_entry(
                st.session_state['username'],
                st.session_state['master_key'],
                st.session_state['signing_key'],
                entry_text
            )
            if success:
                st.success(message)
            else:
                st.error(message)

def show_my_entries_page():
    st.title(f"My Journal Entries for {st.session_state['username']}")
    
    entries = backend.read_user_entries(st.session_state['username'])

    if not entries:
        st.info("You have no journal entries yet.")
        return
        
    for entry in entries:
        with st.expander(f"Entry ID: {entry['id']}"):
            if entry['verified']:
                st.success("✔️ Signature Verified")
                decrypted_message = backend.decrypt_entry_data(
                    st.session_state['master_key'],
                    entry['data']
                )
                st.markdown(f"> {decrypted_message}")
            else:
                st.error(f"❌ {entry['message']}")


def show_share_entry_page():
    st.title("Share an Entry")
    entries = backend.read_user_entries(st.session_state['username'])
    entry_ids = [e['id'] for e in entries if e['verified']]

    if not entry_ids:
        st.warning("You have no verified entries to share.")
        return

    with st.form("share_form"):
        entry_id = st.selectbox("Select Entry ID to share:", options=entry_ids)
        recipient = st.text_input("Recipient's Username:")
        submitted = st.form_submit_button("Share")

        if submitted:
            success, message = backend.share_entry(
                st.session_state['username'],
                st.session_state['master_key'],
                recipient,
                entry_id
            )
            if success:
                st.success(message)
            else:
                st.error(message)

def show_shared_with_me_page():
    st.title("Entries Shared With Me")
    
    shared_entries = backend.view_shared_entries(
        st.session_state['username'],
        st.session_state['signing_key']
    )

    if not shared_entries:
        st.info("No entries have been shared with you.")
        return

    for entry in shared_entries:
        with st.expander(f"Entry from {entry['owner']} (ID: {entry['id']})"):
            st.markdown(f"> {entry['message']}")

def show_account_settings_page():
    st.title("Account Settings")
    
    st.subheader("Change Password")
    
    # Display password requirements
    st.info("""
    **New Password Requirements:**
    - Minimum 8 characters
    - At least one number (0-9)
    - At least one special character (!@#$%^&*(),.?":{}|<>)
    """)
    
    with st.form("change_password_form"):
        current_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password", help="Must be at least 8 characters with a number and special character")
        confirm_password = st.text_input("Confirm New Password", type="password")
        submitted = st.form_submit_button("Change Password")
        
        if submitted:
            if not current_password or not new_password or not confirm_password:
                st.error("All fields are required.")
            elif new_password != confirm_password:
                st.error("New passwords do not match.")
            else:
                # Backend validation will check all password requirements
                success, message = backend.change_password(
                    st.session_state['username'],
                    current_password,
                    new_password
                )
                if success:
                    st.success(message)
                    st.warning("⚠️ You will be logged out. Please log in again with your new password.")
                    # Clear session state to force re-login
                    if st.button("Logout Now"):
                        for key in list(st.session_state.keys()):
                            del st.session_state[key]
                        st.rerun()
                else:
                    st.error(message)
    
    st.divider()
    
    st.subheader("Change Username")
    st.info("⚠️ Changing your username will update all your journal entries and shared entries. This action cannot be undone.")
    with st.form("change_username_form"):
        password = st.text_input("Enter Password to Confirm", type="password", key="username_password")
        new_username = st.text_input("New Username")
        submitted_username = st.form_submit_button("Change Username")
        
        if submitted_username:
            if not password or not new_username:
                st.error("Both password and new username are required.")
            elif new_username == st.session_state['username']:
                st.error("New username must be different from current username.")
            elif len(new_username) < 3:
                st.error("Username must be at least 3 characters long.")
            else:
                success, message = backend.change_username(
                    st.session_state['username'],
                    password,
                    new_username
                )
                if success:
                    st.success(message)
                    st.warning("⚠️ You will be logged out. Please log in again with your new username.")
                    # Clear session state to force re-login
                    if st.button("Logout Now", key="logout_after_username"):
                        for key in list(st.session_state.keys()):
                            del st.session_state[key]
                        st.rerun()
                else:
                    st.error(message)


# --- Main App Logic ---

st.sidebar.title("Secure Journal")

if st.session_state['logged_in']:
    st.sidebar.success(f"Logged in as **{st.session_state['username']}**")
    
    page = st.sidebar.radio(
        "Navigation",
        ["Write Entry", "My Entries", "Share Entry", "View Shared with Me", "Account Settings"]
    )
    
    if st.sidebar.button("Logout"):
        # Clear session state
        for key in st.session_state.keys():
            del st.session_state[key]
        st.rerun()

else:
    page = st.sidebar.radio("Navigation", ["Login", "Register"])

# --- Page Routing ---
if page == "Login":
    show_login_page()
elif page == "Register":
    show_register_page()
elif page == "Write Entry":
    show_write_entry_page()
elif page == "My Entries":
    show_my_entries_page()
elif page == "Share Entry":
    show_share_entry_page()
elif page == "View Shared with Me":
    show_shared_with_me_page()
elif page == "Account Settings":
    show_account_settings_page()
