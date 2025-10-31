# app.py — Streamlit Voting App using Supabase backend

import streamlit as st
import hashlib
import pandas as pd
import matplotlib.pyplot as plt
from supabase import create_client, Client

# --- Supabase setup ---
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- Helper functions for DB operations ---
def verify_user(username, password):
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    resp = supabase.table("users").select("password_hash, role").eq("username", username).execute()
    if resp.data and len(resp.data) > 0:
        rec = resp.data[0]
        if rec["password_hash"] == pw_hash:
            return True, rec["role"]
    return False, None

def add_user(username, password, role):
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        supabase.table("users").insert({"username": username, "password_hash": pw_hash, "role": role}).execute()
        return True
    except Exception as e:
        return False

def reset_password(username, new_password):
    pw_hash = hashlib.sha256(new_password.encode()).hexdigest()
    supabase.table("users").update({"password_hash": pw_hash}).eq("username", username).execute()

def get_all_users():
    resp = supabase.table("users").select("username, role").execute()
    return pd.DataFrame(resp.data or [])

def get_all_votes():
    resp = supabase.table("votes").select("*").execute()
    return pd.DataFrame(resp.data or [])

def has_voted(username):
    resp = supabase.table("votes").select("*").eq("username", username).execute()
    return bool(resp.data and len(resp.data) > 0)

def record_votes(username, tower_votes):
    rows = []
    for tower, candidates in tower_votes.items():
        for candidate in candidates:
            rows.append({"username": username, "tower": tower, "candidate": candidate})
    if rows:
        supabase.table("votes").insert(rows).execute()

def show_vote_summary():
    df = get_all_votes()
    if df.empty:
        st.info("No votes yet.")
        return
    st.subheader("📊 Vote Summary by Tower")
    summary = df.groupby(["tower","candidate"]).size().reset_index(name="votes")
    for tower in summary["tower"].unique():
        sub = summary[summary["tower"] == tower]
        st.write(f"### 🏙️ {tower}")
        fig, ax = plt.subplots()
        ax.bar(sub["candidate"], sub["votes"], color='skyblue')
        ax.set_xlabel("Candidate")
        ax.set_ylabel("Votes")
        ax.set_title(f"Votes for {tower}")
        st.pyplot(fig)

def download_csv(df, name):
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button(f"📥 Download {name} CSV", data=csv, file_name=f"{name}.csv", mime="text/csv")

# --- Main App Logic ---
def main():
    st.set_page_config(page_title="TTGRWA Voting 2025", layout="centered")
    st.title("TTGRWA Voting App")

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.role = None

    if not st.session_state.logged_in:
        st.subheader("🔐 Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            ok, role = verify_user(username, password)
            if ok:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.role = role
                st.success(f"Welcome, {username}!")
            else:
                st.error("Invalid username or password.")
        return

    username = st.session_state.username
    role = st.session_state.role
    st.sidebar.write(f"👤 Logged in as **{username} ({role})**")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False

    # --- Admin Panel ---
    if role == "admin":
        st.subheader("🧑‍💼 Admin Dashboard")
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "👥 Manage Users",
            "🗳️ View Votes",
            "📊 Vote Summary",
            "➕ Add User",
            "🔑 Reset Password"
        ])

        with tab1:
            st.write("### All Registered Users")
            df_users = get_all_users()
            st.dataframe(df_users)
            download_csv(df_users, "users")

        with tab2:
            st.write("### All Votes")
            df_votes = get_all_votes()
            if not df_votes.empty:
                st.dataframe(df_votes)
                download_csv(df_votes, "votes")
            else:
                st.info("No votes recorded yet.")

        with tab3:
            show_vote_summary()

        with tab4:
            st.write("### ➕ Create a New User")
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            new_role = st.selectbox("Role", ["user", "admin"])
            if st.button("Create User"):
                if not new_username or not new_password:
                    st.warning("Please fill out all fields.")
                else:
                    success = add_user(new_username, new_password, new_role)
                    if success:
                        st.success(f"✅ User '{new_username}' created successfully!")
                    else:
                        st.error("Username already exists or error.")

        with tab5:
            st.write("### 🔑 Reset a User's Password")
            df_users2 = get_all_users()
            usernames = df_users2["username"].tolist() if not df_users2.empty else []
            selected_user = st.selectbox("Select user to reset password", usernames)
            new_pw = st.text_input("Enter new password", type="password")
            if st.button("Reset Password"):
                if not new_pw:
                    st.warning("Please enter a new password.")
                else:
                    reset_password(selected_user, new_pw)
                    st.success(f"✅ Password for '{selected_user}' has been reset.")

        return

    # --- User Panel ---
    if role == "user":
        if has_voted(username):
            st.info("✅ You have already submitted your vote. Thank you for participating!")
            return

        st.subheader("🗳️ Submit Your Votes")
        name = st.text_input("Your Name")
        building = st.text_input("Building Number")
        flat = st.text_input("Flat Number")
        consent = st.checkbox("I consent to submit my vote")

        if consent:
            towers = ["T5", "T6", "T7", "T16", "T17", "T18", "T19"]
            candidates = {
                "T5": ["Alice", "Bob", "Charlie"],
                "T6": ["David", "Eve", "Frank"],
                "T7": ["Grace", "Hank", "Ivy"],
                "T16": ["Jack", "Kara", "Leo"],
                "T17": ["Mona", "Ned", "Olive"],
                "T18": ["Paul", "Quinn", "Rose"],
                "T19": ["Sam", "Tina", "Uma"]
            }

            tower_votes = {}
            for tower in towers:
                selected = st.multiselect(f"Select up to 2 candidates for {tower}", candidates[tower], max_selections=2)
                tower_votes[tower] = selected

            if st.button("Submit Votes"):
                record_votes(username, tower_votes)
                st.success("✅ Your votes have been submitted successfully!")
                st.info("Your vote has been recorded. You may now close the app.")
                st.stop()


if __name__ == "__main__":
    main()
