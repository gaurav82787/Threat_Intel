from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from Feeds.Feeds import *
from Log_Analysis import analyze as LA
import argparse
import secrets
import shutil
import gzip
import tarfile
import cgi
import json
from datetime import datetime

Log_Dirrectory = "Log_Analysis/Collected_Logs"
Mal_Traffic_Directory = "Traffic_Analysis/Captured_Malicious_Traffic"
os.makedirs(Log_Dirrectory, exist_ok=True)
os.makedirs(Mal_Traffic_Directory, exist_ok=True)
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
                    collection= p_db['Agents']
                    query = {'token': token}
                    agent = collection.find_one(query)
                    if agent:
                        if 'file' in form:
                            file_item = form['file']
                            if file_item.file:
                                file_name = form.getfirst('file_name')
                                file_ext = form.getfirst('file_ext')
                                print(file_ext)
                                if file_ext=="pcap":
                                    file_path = os.path.join(Mal_Traffic_Directory,agent['Agent_Name'], file_name)  
                                    os.makedirs(os.path.join(Mal_Traffic_Directory,agent['Agent_Name']), exist_ok=True)                             
                                elif file_ext=="log":
                                    file_path = os.path.join(Log_Dirrectory,agent['Agent_Name'], file_name)
                                    os.makedirs(os.path.join(Log_Dirrectory,agent['Agent_Name']), exist_ok=True) 
                                     
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
                                if file_ext=="log":
                                    matched_client_logs= LA.read_and_compare_logs(decompressed_file_path)
                                    if matched_client_logs:
                                        for log in matched_client_logs:
                                            a_db=client["Alerts"]
                                            if agent["Agent_Name"] not in a_db.list_collection_names():
                                                a_db.create_collection(agent["Agent_Name"])
                                            a_collection=a_db[agent['Agent_Name']]
                                            query = {'message': log}
                                            entry = a_collection.find_one(query)
                                            if not entry:
                                                a_collection.insert_one({"date_time": datetime.now().isoformat(), "category": "mal_logs","message": log,"severity": "moderate", "description": "logs in comparison with stored mal logs"}) 

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
        elif self.path=="/alert":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                json_data = json.loads(post_data)    
                token=json_data["token"]
                collection= p_db['Agents']
                query = {'token': token}
                agent = collection.find_one(query)
                if agent:
                    a_db=client["Alerts"]
                    if agent["Agent_Name"] not in a_db.list_collection_names():
                        a_db.create_collection(agent["Agent_Name"])
                    a_collection=a_db[agent['Agent_Name']]
                    a_collection.delete_many({'date_time': {'$lt':datetime.now().isoformat()},'category':json_data['category'],'message': json_data['message']})
                    a_collection.insert_one({"date_time": datetime.now().isoformat(), "category": json_data['category'],"message": json_data['message'],"severity": json_data['severity'], "description": json_data['description']})                  
                    print(json_data['message'])
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"message": "Alert Recieved"}')
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

# ------------------Agent code start---------------------
def add_agent(agent_name,agent_ip):
    agent_ip = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', agent_ip)
    if agent_ip==[]:
        print("Enter Valid IP")
    else:
        if "Agents" not in p_db.list_collection_names():
            p_db.create_collection("Agents")
        query = {'Agent_IP': agent_ip[0]}
        query1 = {'Agent_Name': agent_name}
        collections = p_db["Agents"]
        ip = collections.find_one(query)
        name = collections.find_one(query1)
        if ip or name:
            if ip and name:
                agent_name=name['Agent_Name']
                agent_ip=ip['Agent_IP']
            if not ip and name:
                agent_ip="_"
                agent_name=name['Agent_Name']
            if not name and ip:
                agent_name="_"
                agent_ip=ip['Agent_IP']
            print(f"IP {agent_ip} and Name \"{agent_name}\" Already Exists") 
        else:
            token = generate_token()
            collections.insert_one({'Agent_Name':agent_name, 'Agent_IP': agent_ip[0],'token':token})         
            print(f"Agent {agent_ip} added.\nPaste {token} in Agent application if agent IP not in Subent")
def show_agents():
    all_agents = p_db["Agents"].find()
    try:
        for item in all_agents:
            print(f"{item['Agent_Name']} : {item['Agent_IP']} : Token - {item['token']}")
    except Exception as e:
        print(e)

def generate_token(length=32):
    return secrets.token_hex(length)
# ------------------Agent code End---------------------------

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=80):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting httpd server on port {port}')
    httpd.serve_forever()

def options():
    parser = argparse.ArgumentParser(description='-aF <feed_type> <feed_url> for ADD feed \n -uF for Sync Feed Data')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-aF', '--add_feed', nargs=2, metavar=('FEED_TYPE', 'FEED_URL'), help=f'Enter <{feed_types}> <Feed_URL>')
    group.add_argument('-uF', '--update_feed', action='store_true', help='Synchronize The Feed URLs to Database')
    # group.add_argument('-I', '--init_feed', action='store_true', help='First Step to Initialize the New Feed Types')
    group.add_argument('-aAF', '--add_api_feed', nargs=2, metavar=('server_url', 'api_key'), help='Enter <Feed_URL> <API_KEY>')
    group.add_argument('-aAG', '--add_agent', nargs=2, metavar=('Agent_Name', 'Agent_IP'), help='<agent_name> <agent_IP>')
    group.add_argument('-sAG', '--show_agents', action='store_true', help='show_agents')
    group.add_argument('-rIP', '--restrict_ip', nargs=2, metavar=('ip', 'message'), help='Restrict an IP and add message to it')
    group.add_argument('-srIP', '--show_restrict_ip', action='store_true', help='Show all restricted IPs')
    group.add_argument('-rDir', '--restrict_directory', nargs=1, metavar=('Dir'), help='Restrict an Directory from having Access')
    group.add_argument('-srDir', '--show_restrict_directory', action='store_true', help='Show all restricted Directories')
    group.add_argument('-CTI', '--Start_CTI_Server', action='store_true', help='show_agents')
    args = parser.parse_args()
    
    if args.add_feed:
        feed_type, feed_url = args.add_feed
        add_feed(feed_type, feed_url)
    elif args.update_feed:
        update_feed()
    # elif args.init_feed:
    #     init_feeds()
    elif args.add_api_feed:
        server_url, api_key = args.add_api_feed
        add_api_feed(server_url,api_key)   
    elif args.add_agent:
        agent_name, agent_ip = args.add_agent
        if agent_name=="_" or agent_ip=="_":
            print("Enter Valid Name")
        else:
            add_agent(agent_name,agent_ip)
    elif args.show_agents:
        show_agents()
    elif args.restrict_ip:
        ip, msg = args.restrict_ip
        Restrict_IP(ip,msg)
    elif args.restrict_directory:
        dir, = args.restrict_directory
        Restricted_Directories(dir)
    elif args.show_restrict_ip:
        show_restricted_ip()
    elif args.show_restrict_directory:
        show_restricted_directories()
    elif args.Start_CTI_Server:
        run()
    else:
        parser.print_help()
if __name__ == '__main__':
    options()
    # run()
