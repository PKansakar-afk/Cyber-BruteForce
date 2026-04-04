from datetime import datetime, timedelta
import pandas as pd
from collections import deque

def add_attempt(history, username, ip, status):
    history.append(
        {
            "timestamp": datetime.now(),
            "username": username,
            "ip": ip,
            "status": status,
        }
    )
    return history


def get_failed_attempts(history):
    if not history:
        return pd.DataFrame(columns=["timestamp", "username", "ip", "status"])

    df = pd.DataFrame(history)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    failed_df = df[df["status"] == "FAIL"].copy()
    failed_df = failed_df.sort_values("timestamp")
    return failed_df


def detect_burst_failures(failed_df, threshold=5, window_seconds=60):
    alerts = []
    if failed_df.empty:
        return alerts

    records = failed_df.to_dict("records")
    window = deque()
    last_alert_time = None

    for row in records:
        window.append(row)
        
        # Slide the window: remove records older than our window_seconds
        while window and (row["timestamp"] - window[0]["timestamp"]).total_seconds() > window_seconds:
            window.popleft()

        # If our current sliding window hits the threshold
        if len(window) >= threshold:
            # Only trigger a new alert if we are outside the previous alert's cooldown window
            if last_alert_time is None or (row["timestamp"] - last_alert_time).total_seconds() > window_seconds:
                ips = set(r["ip"] for r in window)
                alerts.append(
                    {
                        "type": "Burst Failure",
                        "severity": "High",
                        "message": f"{len(window)} failed attempts within {window_seconds} seconds",
                        "ips": ", ".join(sorted(ips)),
                    }
                )
                last_alert_time = row["timestamp"]

    return alerts


def detect_suspicious_ips(failed_df, threshold=8, unique_user_threshold=3):
    alerts = []
    if failed_df.empty:
        return alerts

    grouped = failed_df.groupby("ip")

    for ip, group in grouped:
        fail_count = len(group)
        unique_users = group["username"].nunique()

        if fail_count >= threshold or unique_users >= unique_user_threshold:
            alerts.append(
                {
                    "type": "Suspicious IP",
                    "severity": "Medium",
                    "message": f"IP {ip} has {fail_count} failed attempts and targeted {unique_users} username(s)",
                    "ip": ip,
                }
            )

    return alerts


def detect_targeted_accounts(failed_df, threshold=5, window_minutes=5):
    alerts = []
    if failed_df.empty:
        return alerts

    grouped = failed_df.groupby("username")

    for username, group in grouped:
        # Sort group by timestamp just in case
        group = group.sort_values("timestamp")
        records = group.to_dict("records")
        
        window = deque()
        last_alert_time = None # FIX APPLIED HERE

        for row in records:
            window.append(row)
            
            # Slide the window: remove records older than our window_minutes
            while window and (row["timestamp"] - window[0]["timestamp"]).total_seconds() > (window_minutes * 60):
                window.popleft()

            if len(window) >= threshold:
                # FIX APPLIED HERE
                if last_alert_time is None or (row["timestamp"] - last_alert_time).total_seconds() > (window_minutes * 60):
                    alerts.append(
                        {
                            "type": "Targeted Account",
                            "severity": "High",
                            "message": f"Account '{username}' has {len(window)} failed attempts within {window_minutes} minutes",
                            "username": username,
                        }
                    )
                    last_alert_time = row["timestamp"]

    return alerts


def generate_alerts(history):
    failed_df = get_failed_attempts(history)

    alerts = []
    alerts.extend(detect_burst_failures(failed_df))
    alerts.extend(detect_suspicious_ips(failed_df))
    alerts.extend(detect_targeted_accounts(failed_df))

    return alerts, failed_df


def generate_summary(history, failed_df, alerts):
    total_attempts = len(history)
    total_failures = len(failed_df)

    suspicious_ips = set()
    targeted_accounts = set()

    for alert in alerts:
        if alert["type"] == "Suspicious IP" and "ip" in alert:
            suspicious_ips.add(alert["ip"])
        if alert["type"] == "Targeted Account" and "username" in alert:
            targeted_accounts.add(alert["username"])

    return {
        "total_attempts": total_attempts,
        "total_failures": total_failures,
        "suspicious_ip_count": len(suspicious_ips),
        "targeted_account_count": len(targeted_accounts),
        "alert_count": len(alerts),
    }