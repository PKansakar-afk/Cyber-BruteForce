import streamlit as st
import pandas as pd
import ipaddress
import time
import os

from detector import add_attempt, generate_alerts, generate_summary

st.set_page_config(page_title="Brute-Force Attempt Detector", layout="wide")

st.title("Brute-Force Attempt Detector Dashboard")
st.write("Simulated login attempts with brute-force detection alerts.")

# Simulated users
USERS = {
    "alice": "alice123",
    "bob": "bob123",
    "admin": "admin123",
}

# Session state
if "history" not in st.session_state:
    st.session_state.history = []

if "last_result" not in st.session_state:
    st.session_state.last_result = None

# Sidebar
st.sidebar.header("Detection Rules")
st.sidebar.write("- Burst failures: 5 failures within 60 seconds")
st.sidebar.write("- Suspicious IP: 8 failures or 3 usernames from same IP")
st.sidebar.write("- Targeted account: 5 failures within 5 minutes")

# Login form
st.subheader("Simulated Login")

col1, col2, col3 = st.columns(3)

with col1:
    username = st.text_input("Username", placeholder="Enter username")

with col2:
    password = st.text_input("Password", type="password", placeholder="Enter password")

with col3:
    ip = st.text_input("Source IP", placeholder="e.g. 192.168.1.10")

login_clicked = st.button("Login")

if login_clicked:
    if not username or not password or not ip:
        st.warning("Please fill in username, password, and source IP.")
    else:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            st.error("Invalid IP address format.")
            st.stop()

        if username in USERS and USERS[username] == password:
            status = "SUCCESS"
            st.session_state.last_result = "SUCCESS"
            st.success("Login successful")
        else:
            status = "FAIL"
            st.session_state.last_result = "FAIL"
            st.error("Login failed")

        st.session_state.history = add_attempt(
            st.session_state.history, username, ip, status
        )

# Last login result
st.subheader("Last Login Result")
if st.session_state.last_result == "SUCCESS":
    st.success("Last attempt: SUCCESS")
elif st.session_state.last_result == "FAIL":
    st.error("Last attempt: FAIL")
else:
    st.info("No login attempt submitted yet.")

# Generate alerts and summary
alerts, failed_df = generate_alerts(st.session_state.history)
summary = generate_summary(st.session_state.history, failed_df, alerts)

# Summary
st.subheader("Summary")
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Attempts", summary["total_attempts"])
m2.metric("Failed Attempts", summary["total_failures"])
m3.metric("Suspicious IPs", summary["suspicious_ip_count"])
m4.metric("Targeted Accounts", summary["targeted_account_count"])
m5.metric("Alerts", summary["alert_count"])

# Alerts section
st.subheader("Alerts")
if alerts:
    for alert in alerts:
        st.warning(f"[{alert['severity']}] {alert['type']}: {alert['message']}")
else:
    st.info("No brute-force alerts detected yet.")

# History
st.subheader("Login Attempt History")
if st.session_state.history:
    history_df = pd.DataFrame(st.session_state.history)
    history_df["timestamp"] = pd.to_datetime(history_df["timestamp"])
    history_df = history_df.sort_values("timestamp", ascending=False)
    st.dataframe(history_df, use_container_width=True)
else:
    st.info("No login attempts yet.")

# Failed attempts table
st.subheader("Failed Login Attempts")
if not failed_df.empty:
    failed_display_df = failed_df.copy()
    failed_display_df["timestamp"] = pd.to_datetime(failed_display_df["timestamp"])
    failed_display_df = failed_display_df.sort_values("timestamp", ascending=False)
    st.dataframe(failed_display_df, use_container_width=True)
else:
    st.info("No failed login attempts yet.")

# Charts
st.subheader("Charts")
if not failed_df.empty:
    col_a, col_b = st.columns(2)

    with col_a:
        st.write("Failed Attempts by IP")
        ip_counts = failed_df["ip"].value_counts()
        st.bar_chart(ip_counts)

    with col_b:
        st.write("Failed Attempts by Username")
        user_counts = failed_df["username"].value_counts()
        st.bar_chart(user_counts)
else:
    st.info("Charts will appear after failed login attempts are recorded.")

# CSV log analysis
st.subheader("CSV Log Analysis")

uploaded_file = st.file_uploader("Upload a CSV log file", type=["csv"])

if uploaded_file is not None:
    csv_df = pd.read_csv(uploaded_file)
    st.write("Uploaded Log Data")
    st.dataframe(csv_df, use_container_width=True)

    required_columns = {"timestamp", "username", "ip", "status"}

    if required_columns.issubset(set(csv_df.columns)):
        temp_history = csv_df.to_dict("records")
        alerts_csv, failed_csv = generate_alerts(temp_history)
        summary_csv = generate_summary(temp_history, failed_csv, alerts_csv)

        st.write("CSV Analysis Summary")
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Attempts", summary_csv["total_attempts"])
        c2.metric("Failed Attempts", summary_csv["total_failures"])
        c3.metric("Suspicious IPs", summary_csv["suspicious_ip_count"])
        c4.metric("Targeted Accounts", summary_csv["targeted_account_count"])
        c5.metric("Alerts", summary_csv["alert_count"])

        st.write("CSV Alerts")
        if alerts_csv:
            for alert in alerts_csv:
                st.warning(f"[{alert['severity']}] {alert['type']}: {alert['message']}")
        else:
            st.info("No brute-force alerts detected in uploaded CSV.")
    else:
        st.error("CSV must contain these columns: timestamp, username, ip, status")

# Reset button
if st.button("Reset History"):
    st.session_state.history = []
    st.session_state.last_result = None
    st.rerun()

st.divider()
st.subheader("Live Log Monitoring (Real-Time)")

# A toggle switch to turn live mode on and off
live_mode = st.toggle("Enable Live Monitoring")

if live_mode:
    # Initialize file tracking in session state
    if "last_line_read" not in st.session_state:
        st.session_state.last_line_read = 1 # Skip header line
    
    live_file = os.path.join("live_logs", "live_logs.csv")
    
    if os.path.exists(live_file):
        with open(live_file, "r") as f:
            lines = f.readlines()
            total_lines = len(lines)
            
            if total_lines > st.session_state.last_line_read:
                new_lines = lines[st.session_state.last_line_read:]
                
                # Parse the new lines and add them to our history
                for line in new_lines:
                    # Clean the line and split by CSV comma
                    parts = line.strip().split(",")
                    if len(parts) == 4:
                        timestamp, user, ip, status = parts
                        st.session_state.history.append({
                            "timestamp": pd.to_datetime(timestamp),
                            "username": user,
                            "ip": ip,
                            "status": status
                        })
                
                # Update bookmark
                st.session_state.last_line_read = total_lines
                
        # Re-run detection on the updated history
        live_alerts, live_failed_df = generate_alerts(st.session_state.history)
        
        # Display a live metric
        st.metric("Total Logs Ingested", len(st.session_state.history))
        
        # Flash an alert if something new was caught
        if live_alerts:
            st.error("THREAT DETECTED!!!")
            # Show the most recent 3 alerts
            for alert in live_alerts[-3:]: 
                st.warning(f"[{alert['severity']}] {alert['type']}: {alert['message']}")
    else:
        st.info("Waiting for live_logs.csv to be created. Run your traffic simulator!")

    # Pause for 2 seconds, then refresh the whole dashboard automatically
    time.sleep(2)
    st.rerun()