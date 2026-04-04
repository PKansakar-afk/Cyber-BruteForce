import csv
import random
import time
import os
from datetime import datetime

OUTPUT_DIR = "live_logs"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "live_logs.csv")
USERS = ["alice", "bob", "admin", "charlie"]
NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 20)]
ATTACKER_IP = "203.0.113.42"

def simulate_live_traffic():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Starting live traffic simulation... Writing to {OUTPUT_FILE}")
    print("Press Ctrl+C to stop.")
    
    # Create file with headers if it doesn't exist
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["timestamp", "username", "ip", "status"])

    try:
        while True:
            # Decide if this is a normal login or an attack burst
            is_attack = random.random() < 0.2  # 20% chance to trigger an attack burst
            
            with open(OUTPUT_FILE, mode="a", newline="") as file:
                writer = csv.writer(file)
                
                if is_attack:
                    # Burst of 5-8 failed attempts in under a second
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Launching attack burst!")
                    burst_size = random.randint(5, 8)
                    for _ in range(burst_size):
                        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                        writer.writerow([timestamp_str, "admin", ATTACKER_IP, "FAIL"])
                else:
                    # Normal background traffic
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Normal login")
                    user = random.choice(USERS)
                    ip = random.choice(NORMAL_IPS)
                    status = "SUCCESS" if random.random() < 0.8 else "FAIL"
                    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                    writer.writerow([timestamp_str, user, ip, status])

            # Wait 1 to 3 seconds before the next log event
            time.sleep(random.uniform(1.0, 3.0))
            
    except KeyboardInterrupt:
        print("\nSimulation stopped.")

if __name__ == "__main__":
    simulate_live_traffic()