python3 -m venv venv

source venv/bin/activate

##pip install -r requirements.txt

python -m pip install --upgrade pip

python -m pip install -r requirements.txt

python -m streamlit run app.py



# Changes made

- Optimized Detection Logic 
  (O(N) vs O(N^2)). 
  Replaced the nested for loops with a Sliding Window using collections.deque.
  Useful for stress testing.
  File changed (detector.py), functions changed (detect_burst_failures, detect_targeted_accounts)

- Stress Testing
  Created a stress-test script that generates 25,000+ records with randomized attack patterns. (generate_logs.py)

- Real-Time Attack Detection
  (live_traffic_simulator.py) appends logs to a CSV in a live_logs/ folder and the app continuously checks the file.

- Time-Series Graph
  Just a new graph for failed attempts over time.