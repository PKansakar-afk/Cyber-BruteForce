import csv
import random
import os
from datetime import datetime, timedelta

# Configuration
NUM_RECORDS = 25000
OUTPUT_DIR = "generated_logs"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "stress_test_logs.csv")

# Sample Data Pool
USERS = ["alice", "bob", "admin", "charlie", "david", "eve", "frank", "grace"]
NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
ATTACKER_IPS = ["203.0.113.42", "198.51.100.7", "10.0.0.99"]

def generate_csv():
    # Create the target directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    print(f"Generating {NUM_RECORDS} records... Please wait.")
    
    # Start the log 24 hours ago
    current_time = datetime.now() - timedelta(days=1)
    
    with open(OUTPUT_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "username", "ip", "status"])
        
        for i in range(NUM_RECORDS):
            current_time += timedelta(seconds=random.uniform(0.1, 3.5))
            
            if random.random() < 0.85:
                user = random.choice(USERS)
                ip = random.choice(NORMAL_IPS)
                status = "SUCCESS" if random.random() < 0.9 else "FAIL"
                
            else:
                ip = random.choice(ATTACKER_IPS)
                
                if ip == "203.0.113.42":
                    user = "admin"
                elif ip == "198.51.100.7":
                    user = random.choice(USERS)
                else:
                    user = "bob"
                    
                status = "FAIL"
            
            timestamp_str = current_time.strftime("%Y-%m-%d %H:%M:%S.%f")
            writer.writerow([timestamp_str, user, ip, status])

    print(f"Done! {OUTPUT_FILE} has been created.")

if __name__ == "__main__":
    generate_csv()