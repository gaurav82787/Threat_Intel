import ast
from pymongo import MongoClient

server_ip=""
server_port=""
log_files_to_watch = []
auth_token=""

try:
    with open('secret', 'r') as f:
        auth_token= f.readline().strip()
except:
    print("Token Not Present or Not There")

config_file='prava_agent.conf'
with open(config_file, 'r') as file:
    for line in file:
        # Strip whitespace and check if the line is not a comment
        line = line.strip()
        if line and not line.startswith('#'):
            # Process the line based on its content
            if line.startswith('server_address'):
                server_ip = line.split()[1]
            elif line.startswith('server_port'):
                server_port = int(line.split()[1])
            elif line.startswith('log_files'):
                log_files_str = line.split(maxsplit=1)[1]     
                # Convert the string representation of the list into an actual Python list
                try:
                     log_files_to_watch = ast.literal_eval(log_files_str)
                except (SyntaxError, ValueError) as e:
                    print(f"Error parsing log files: {e}")

client = MongoClient(f"mongodb://agent:agent1234@{server_ip}:27017/?authSource=Threat_Intel")
db = client["Threat_Intel"]