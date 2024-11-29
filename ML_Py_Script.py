import pandas as pd
import time
import os
from sklearn.cluster import KMeans
from tkinter import messagebox, Tk

# Configuration
LOG_FILE = "/var/log/anomaly_monitor.log"
CHECK_INTERVAL = 10  # seconds
THRESHOLDS = {"CPU": 80000, "MEM": 100000, "SEND": 10, "RECV": 50}  # Current thresholds

def load_logs(log_file):
    """Load and parse logs from the file."""
    logs = []
    if not os.path.exists(log_file):
        print(f"Log file {log_file} does not exist.")
        return pd.DataFrame()

    print(f"Reading log file: {log_file}")
    with open(log_file, 'r') as f:
        for line_num, line in enumerate(f, start=1):
            if not line.strip() or "PID" not in line:
                print(f"Skipped line {line_num}: {line.strip()}")
                continue
            try:
                parts = line.strip().split()
                log_entry = {
                    "PID": int(parts[2].split(":")[1]),
                    "COMM": parts[3].split(":")[1],
                    "CPU": int(parts[4].split(":")[1]),
                    "MEM": int(parts[5].split(":")[1]),
                    "SEND": int(parts[6].split(":")[1]),
                    "RECV": int(parts[7].split(":")[1]),
                }
                logs.append(log_entry)
                print(f"Successfully parsed line {line_num}: {log_entry}")
            except Exception as e:
                print(f"Error parsing line {line_num}: {line.strip()} - {e}")
    df = pd.DataFrame(logs)
    print(f"DataFrame created with {len(df)} entries.")
    return df




def detect_anomalies(data, thresholds):
    """Detect anomalies based on current thresholds."""
    anomalies = data[
        (data["CPU"] > thresholds["CPU"]) |
        (data["MEM"] > thresholds["MEM"]) |
        (data["SEND"] > thresholds["SEND"]) |
        (data["RECV"] > thresholds["RECV"])
    ]
    return anomalies


from sklearn.exceptions import ConvergenceWarning
import warnings

def recommend_thresholds(data):
    """Use KMeans to recommend thresholds based on logs."""
    if data.empty:
        print("No data available for threshold recommendation.")
        return THRESHOLDS  # Return default thresholds

    features = data[["CPU", "MEM", "SEND", "RECV"]]
    unique_rows = features.drop_duplicates()

    n_clusters = min(3, unique_rows.shape[0])  # Use at most 3 clusters, but not more than unique rows

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ConvergenceWarning)
        kmeans = KMeans(n_clusters=n_clusters, random_state=0)
        kmeans.fit(unique_rows)

    cluster_centers = kmeans.cluster_centers_
    return {
        "CPU": int(max(cluster_centers[:, 0])),
        "MEM": int(max(cluster_centers[:, 1])),
        "SEND": int(max(cluster_centers[:, 2])),
        "RECV": int(max(cluster_centers[:, 3])),
    }




def show_alert(anomalies):
    """Display a popup alert for detected anomalies."""
    root = Tk()
    root.withdraw()  # Hide the main Tkinter window
    processes = "\n".join(
        f"PID: {row['PID']}, COMM: {row['COMM']}, CPU: {row['CPU']}, MEM: {row['MEM']}, SEND: {row['SEND']}, RECV: {row['RECV']}"
        for _, row in anomalies.iterrows()
    )
    messagebox.showwarning("Anomaly Detected!", f"The following processes exceeded thresholds:\n\n{processes}")
    root.destroy()


def main():
    print("Starting anomaly monitor...")
    while True:
        # Load logs
        data = load_logs(LOG_FILE)
        if data.empty:
            print("Parsed data is empty after loading logs.")
            print("Check filtering criteria or log format.")
        else:
            print("Parsed Data:")
            print(data.head())  # Display first few rows


        if not data.empty:
            # Detect anomalies
            anomalies = detect_anomalies(data, THRESHOLDS)

            if not anomalies.empty:
                show_alert(anomalies)

            # Recommend thresholds
            recommended = recommend_thresholds(data)
            print(f"Recommended thresholds: {recommended}")

        else:
            print("No valid data found.")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()



