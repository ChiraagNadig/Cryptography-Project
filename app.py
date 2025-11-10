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
    with st.form("register_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Register")

        if submitted:
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


# --- Main App Logic ---

st.sidebar.title("Secure Journal")

if st.session_state['logged_in']:
    st.sidebar.success(f"Logged in as **{st.session_state['username']}**")
    
    page = st.sidebar.radio(
        "Navigation",
        ["Write Entry", "My Entries", "Share Entry", "View Shared with Me"]
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
