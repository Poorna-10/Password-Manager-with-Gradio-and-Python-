import streamlit as st
import json
import os
import string
import secrets
import base64
import hashlib
import matplotlib.pyplot as plt
from cryptography.fernet import Fernet

# === File paths ===
DATA_FILE = "vault.json"
MASTER_HASH = "master.hash"

# === Key & Encryption Handling ===
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def load_fernet(password):
    key = generate_key(password)
    return Fernet(key)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# === Master Password Handling ===
def check_master_password(input_password):
    if not os.path.exists(MASTER_HASH):
        with open(MASTER_HASH, "w") as f:
            f.write(hash_password(input_password))
        return True, "Master password set!"
    with open(MASTER_HASH, "r") as f:
        stored_hash = f.read()
    if hash_password(input_password) == stored_hash:
        return True, "Authenticated!"
    return False, "Incorrect password!"

# === Vault Handling ===
def load_vault():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_vault(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# === Password Generator ===
def generate_password(length, upper, digits, symbols):
    chars = string.ascii_lowercase
    if upper: chars += string.ascii_uppercase
    if digits: chars += string.digits
    if symbols: chars += string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def evaluate_strength(password):
    score = 0
    if len(password) >= 12: score += 1
    if any(c.islower() for c in password) and any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in string.punctuation for c in password): score += 1
    return score

def show_strength_chart(score):
    labels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    scores = [0]*5
    scores[score] = 1
    colors = ['red', 'orange', 'yellow', 'green', 'darkgreen']

    fig, ax = plt.subplots()
    ax.bar(labels, scores, color=colors)
    ax.set_ylabel("Strength Level")
    ax.set_title("Password Strength")
    st.pyplot(fig)

# === Streamlit UI ===
st.set_page_config(page_title="🔐 Password Manager", layout="centered")
st.title("🔐 Secure Password Manager")

tab1, tab2, tab3 = st.tabs(["🔏 Add/Retrieve", "🔧 Generate Password", "📊 Vault Stats"])

# === Master Password Section ===
with st.sidebar:
    st.subheader("🔐 Login / Setup")
    master_input = st.text_input("Enter Master Password", type="password")
    if master_input:
        verified, msg = check_master_password(master_input)
        st.success(msg) if verified else st.error(msg)

# === Tab 1: Vault Access ===
with tab1:
    if not master_input:
        st.warning("Please enter the master password in the sidebar.")
    else:
        fernet = load_fernet(master_input)
        st.subheader("🔏 Add Credentials")
        site = st.text_input("Website / App Name")
        username = st.text_input("Username / Email")
        password = st.text_input("Password (leave blank to auto-generate)", type="password")

        if st.button("Save Password"):
            if not password:
                password = generate_password(16, True, True, True)
            enc = fernet.encrypt(password.encode()).decode()
            vault = load_vault()
            vault[site] = {"username": username, "password": enc}
            save_vault(vault)
            st.success(f"Password for {site} saved.")

        st.subheader("🔓 Retrieve Credentials")
        search_site = st.text_input("Enter site name to retrieve")
        if st.button("Fetch"):
            vault = load_vault()
            if search_site in vault:
                enc_pass = vault[search_site]["password"]
                decrypted = fernet.decrypt(enc_pass.encode()).decode()
                st.info(f"Username: {vault[search_site]['username']}")
                st.code(f"Password: {decrypted}", language="text")
            else:
                st.warning("No entry found.")

# === Tab 2: Generator ===
with tab2:
    st.subheader("🔧 Generate Strong Password")
    length = st.slider("Length", 8, 64, 16)
    upper = st.checkbox("Include Uppercase", value=True)
    digits = st.checkbox("Include Digits", value=True)
    symbols = st.checkbox("Include Symbols", value=True)

    if st.button("Generate"):
        gen_pwd = generate_password(length, upper, digits, symbols)
        score = evaluate_strength(gen_pwd)
        st.text_input("Generated Password", gen_pwd)
        st.markdown(f"**Strength:** {['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'][score]}")
        show_strength_chart(score)

# === Tab 3: Stats ===
with tab3:
    if not master_input:
        st.warning("Please enter the master password in the sidebar.")
    else:
        vault = load_vault()
        st.subheader("📊 Vault Summary")
        st.metric("🔐 Total Entries", len(vault))

        if len(vault) > 0:
            sites = list(vault.keys())
            st.write("🔍 Stored Sites")
            st.write(", ".join(sites))
