from datetime import datetime
from elasticsearch import Elasticsearch, helpers
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
import argparse
import secrets

# Disable warnings for insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Elasticsearch connection
es = Elasticsearch(
    [{'host': 'localhost', 'port': 9200, 'scheme': 'https'}],
    basic_auth=('elastic', 'zswNiQjnMnc0Bvg2vjYj'),
    ca_certs='C:\\elasticsearch\\kibana-8.14.2\\data\\ca_1720367038865.crt',
    request_timeout=120  
)

# MongoDB connection
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["log_database"]
malicious_logs_collection = mongo_db["malicious_logs"]

def add_timestamp_to_logs(index_name):
    try:
        query_body = {
            "size": 1000,
            "query": {
                "match_all": {}
            }
        }
        response = es.search(index=index_name, body=query_body)
        hits = response['hits']['hits']

        actions = []
        for hit in hits:
            doc_id = hit['_id']
            doc = hit['_source']
            
            if '@timestamp' not in doc:
                doc['@timestamp'] = datetime.now().isoformat()
                action = {
                    "_op_type": "update",
                    "_index": index_name,
                    "_id": doc_id,
                    "doc": {"@timestamp": doc['@timestamp']}
                }
                actions.append(action)

        if actions:
            helpers.bulk(es, actions)
            print(f"Added @timestamp to {len(actions)} logs in index '{index_name}'")
    except Exception as e:
        print(f"Error adding @timestamp to logs in '{index_name}': {e}")

def fetch_logs(index_name, query_body):
    try:
        response = es.search(index=index_name, body=query_body)
        hits = response['hits']['hits']
        print(f"Fetched {len(hits)} logs from index '{index_name}'")

        return hits
    except Exception as e:
        print(f"Error fetching logs from '{index_name}': {e}")
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
    matched_logs = [log for log in logs if log["_source"]["message"] in malicious_messages]
    return matched_logs

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/yara':
            os.makedirs("Traffic_Analysis/Yara_Rules", exist_ok=True)
            with tarfile.open("Traffic_Analysis/Yara_Rules/Send.gz", "w:gz") as tar:
                tar.add("Traffic_Analysis/Yara_Rules/", arcname=os.path.basename("Traffic_Analysis/Yara_Rules/"))
            try:
                with open("Traffic_Analysis/Yara_Rules/Send.gz", 'rb') as file:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/gzip')
                    self.end_headers()
                    self.wfile.write(file.read())
            except IOError:
                self.send_error(404, 'File Not Found')
            os.remove("Traffic_Analysis/Yara_Rules/Send.gz")
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error": "Not Found"}')
        
    def do_POST(self):
        if self.path == '/upload_file':
            content_type = self.headers.get('Content-Type')        
            if content_type and 'multipart/form-data' in content_type:
                try:             
                    # Parse the form data
                    form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
                    token=form.getfirst('token')
                    collection = mongo_db['Agents']
                    query = {'token': token}
                    agent = collection.find_one(query)
                    if agent:
                        if 'file' in form:
                            file_item = form['file']
                            if file_item.file:
                                file_name = form.getfirst('file_name')
                                file_ext = form.getfirst('file_ext')
                                print(file_ext)
                                if file_ext == "pcap":
                                    file_path = os.path.join(Mal_Traffic_Directory, agent['Agent_Name'], file_name)  
                                    os.makedirs(os.path.join(Mal_Traffic_Directory, agent['Agent_Name']), exist_ok=True)                             
                                elif file_ext == "log":
                                    file_path = os.path.join(Log_Dirrectory, agent['Agent_Name'], file_name)
                                    os.makedirs(os.path.join(Log_Dirrectory, agent['Agent_Name']), exist_ok=True)  
                                with open(file_path, 'wb') as output_file:
                                    shutil.copyfileobj(file_item.file, output_file)
                                # Check file size
                                file_size = os.path.getsize(file_path)
                                print(f"Received file size: {file_size} bytes")

                                if file_size == 0:
                                    raise ValueError("Received file is empty")

                                # Decompress the file
                                decompressed_file_path = file_path.rsplit('.', 1)[0]  # Remove .gz extension
                                with gzip.open(file_path, 'rb') as f_in:
                                    with open(decompressed_file_path, 'wb') as f_out:
                                        shutil.copyfileobj(f_in, f_out)
                                
                                # Remove the compressed file after decompression
                                os.remove(file_path)
                                
                                print(f'File received and saved as {decompressed_file_path}')
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(b'{"message": "File received and saved"}')
                    elif not agent:
                        self.send_response(403)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(b'{"message": "Not Valid Token"}')
                except Exception as e:
                    print(f'Error processing file: {e}')
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"error": "Internal Server Error"}')
            else:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid Content-Type"}')
        elif self.path == "/alert":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                json_data = json.loads(post_data)    
                token = json_data["token"]
                collection = mongo_db['Agents']
                query = {'token': token}
                agent = collection.find_one(query)
                if agent:
                    a_db = mongo_client["Alerts"]
                    if agent["Agent_Name"] not in a_db.list_collection_names():
                        a_db.create_collection(agent["Agent_Name"])
                    a_collection = a_db[agent['Agent_Name']]
                    a_collection.insert_one({"date_time": json_data['date_time'], "category": json_data['category'], "message": json_data['message'], "severity": json_data['severity'], "description": json_data['description']})
                    print(json_data['message'])
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"message": "JSON data received and printed"}')
                else:
                    self.send_response(403)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"message": "Not Valid Token"}')
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid JSON"}')
            except Exception as e:
                print(f'Error processing JSON: {e}')
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error": "Internal Server Error"}')
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error": "Not Found"}')

if __name__ == "__main__":
    # Define directories
    Log_Dirrectory = "Log_Analysis/Collected_Logs"
    Mal_Traffic_Directory = "Traffic_Analysis/Captured_Malicious_Traffic"
    os.makedirs(Log_Dirrectory, exist_ok=True)
    os.makedirs(Mal_Traffic_Directory, exist_ok=True)

    # Define indices and log paths
    client_logs_index = "client_logs"
    server_logs_index = "server_logs"
    malicious_logs_path = "C:\\elasticsearch\\malicious_logs\\malicious_logs.log"

    # Process client logs
    print("Processing client logs...")
    for retry in range(3):
        try:
            add_timestamp_to_logs(client_logs_index)
            query_body_client_logs = {
                "query": {
                    "match_all": {}
                }
            }
            client_logs = fetch_logs(client_logs_index, query_body_client_logs)
            break
        except Exception as e:
            print(f"Retry {retry+1}/3: Error processing client logs: {e}")
            time.sleep(5)

    # Process server logs
    print("Processing server logs...")
    for retry in range(3):
        try:
            add_timestamp_to_logs(server_logs_index)
            query_body_server_logs = {
                "query": {
                    "match_all": {}
                }
            }
            server_logs = fetch_logs(server_logs_index, query_body_server_logs)
            break
        except Exception as e:
            print(f"Retry {retry+1}/3: Error processing server logs: {e}")
            time.sleep(5)

    # Compare client and server logs with malicious logs in MongoDB
    print("Comparing logs with malicious logs in MongoDB...")
    mongodb_malicious_logs = get_malicious_logs_from_mongodb()

    matched_client_logs = compare_logs_with_malicious_logs(client_logs, mongodb_malicious_logs)
    matched_server_logs = compare_logs_with_malicious_logs(server_logs, mongodb_malicious_logs)

    if matched_client_logs:
        print(f"Found {len(matched_client_logs)} malicious logs in client logs.")
        for log in matched_client_logs:
            print(f"Malicious Client Log: {log['_source']['message']}")
    else:
        print("No malicious logs found in client logs.")

    if matched_server_logs:
        print(f"Found {len(matched_server_logs)} malicious logs in server logs.")
        for log in matched_server_logs:
            print(f"Malicious Server Log: {log['_source']['message']}")
    else:
        print("No malicious logs found in server logs.")

    # Read and process malicious logs
    print("Processing malicious logs...")
    malicious_logs = read_log_file(malicious_logs_path)
    if malicious_logs:
        print("Updating MongoDB with new malicious logs...")
        update_malicious_logs_in_mongodb(malicious_logs)
        print(f"Updated {len(malicious_logs)} malicious logs in MongoDB")
    else:
        print("No malicious logs detected from log file.")
