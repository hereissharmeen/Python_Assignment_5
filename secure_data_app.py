import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Setup page
st.set_page_config(page_title="🔐 Secure Data Encryption", layout="centered")

# Generate Fernet key (for demo only — store securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {encrypted_text: {"encrypted_text": x, "passkey": hashed_passkey}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True


# Helpers
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    stored = st.session_state.stored_data

    if encrypted_text in stored and stored[encrypted_text]["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None


# Pages
def show_home():
    st.subheader("🏠 Welcome to Secure Data Encryption App")
    st.markdown("Safely **store** and **retrieve** encrypted text using a custom passkey.")


def store_data_page():
    st.subheader("📥 Store Encrypted Data")
    text = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("Encrypt & Save"):
        if text and passkey:
            encrypted_text = encrypt_data(text, passkey)
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Please enter both data and passkey.")


def retrieve_data_page():
    st.subheader("🔍 Retrieve Your Data")

    if not st.session_state.authorized:
        st.warning("🔐 Please login again to continue.")
        return

    encrypted_text = st.text_area("Enter your encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Data decrypted successfully!")
                st.code(result, language="text")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("🚫 Too many failed attempts. Redirecting to login page...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please enter both fields.")


def login_page():
    st.subheader("🔑 Reauthorization Required")
    password = st.text_input("Enter master password to continue:", type="password")

    if st.button("Login"):
        if password == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Login successful! Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password!")


# Sidebar Navigation
st.sidebar.title("🔐 Navigation")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Go to:", menu)

if choice == "Home":
    show_home()
elif choice == "Store Data":
    store_data_page()
elif choice == "Retrieve Data":
    retrieve_data_page()
elif choice == "Login":
    login_page()
