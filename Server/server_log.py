from datetime import datetime
from pymongo import MongoClient
import urllib3
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import shutil
import gzip
import tarfile
import cgi
import json

# Disable warnings for insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# MongoDB connection
mongo_client = MongoClient("mongodb://root:mongo1234@172.17.0.1:27017/")
mongo_db = mongo_client["log_database"]
malicious_logs_collection = mongo_db["malicious_logs"]

def fetch_logs(collection, query):
    try:
        logs = list(collection.find(query))
        print(f"Fetched {len(logs)} logs from collection '{collection.name}'")
        return logs
    except Exception as e:
        print(f"Error fetching logs from '{collection.name}': {e}")
        return []

def read_log_file(file_path):
    if not os.path.exists(file_path):
        print(f"Error reading log file {file_path}: File does not exist")
        return []

    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
            print(f"Read {len(logs)} logs from file {file_path}")
            return logs
    except Exception as e:
        print(f"Error reading log file {file_path}: {e}")
        return []

def update_malicious_logs_in_mongodb(logs):
    for log in logs:
        log_entry = {
            "message": log.strip(),
            "@timestamp": datetime.now().isoformat()
        }
        # Upsert log into MongoDB
        malicious_logs_collection.update_one(
            {"message": log_entry["message"]},
            {"$set": log_entry},
            upsert=True
        )

def get_malicious_logs_from_mongodb():
    return list(malicious_logs_collection.find({}, {"_id": 0, "message": 1}))

def compare_logs_with_malicious_logs(logs, malicious_logs):
    malicious_messages = {log["message"] for log in malicious_logs}
    matched_logs = [log for log in logs if log.get("message") in malicious_messages]
    return matched_logs


if __name__ == "__main__":
    # Define directories
    Log_Dirrectory = "Log_Analysis/Collected_Logs"
    Mal_Traffic_Directory = "Traffic_Analysis/Captured_Malicious_Traffic"
    os.makedirs(Log_Dirrectory, exist_ok=True)
    os.makedirs(Mal_Traffic_Directory, exist_ok=True)

    # Define log paths
    malicious_logs_path = "Log_Analysis/Malicious_Logs_Samples/malicious_logs.log"

    # Process client logs
    print("Processing client logs...")
    client_logs = fetch_logs(client_logs_collection, {})

    # Compare client and server logs with malicious logs in MongoDB
    print("Comparing logs with malicious logs in MongoDB...")
    mongodb_malicious_logs = get_malicious_logs_from_mongodb()

    matched_client_logs = compare_logs_with_malicious_logs(client_logs, mongodb_malicious_logs)

    if matched_client_logs:
        print(f"Found {len(matched_client_logs)} malicious logs in client logs.")
        for log in matched_client_logs:
            print(f"Malicious Client Log: {log['message']}")
    else:
        print("No malicious logs found in client logs.")

    # Read and process malicious logs
    print("Processing malicious logs...")
    malicious_logs = read_log_file(malicious_logs_path)
    if malicious_logs:
        print("Updating MongoDB with new malicious logs...")
        update_malicious_logs_in_mongodb(malicious_logs)
        print(f"Updated {len(malicious_logs)} malicious logs in MongoDB")
    else:
        print("No malicious logs detected from log file.")
