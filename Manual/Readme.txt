1.Setup ELKM docker container server side -- elastic , logstash ,kibana, mongo
	run: docker-compose up setup
	run: docker-compose up
	Note: elastic,mongo root etc passwords are defined in docker environment itself
root : mongo1234


2. Add some urls in feeds at server side  Note: take feeds_url for some urls 
3. Then update the feed by -uF at server side
4. Add Some Restricted_IP's , Restricted Directories e.g. python server.py -rDir "directory_path"
5. Add agent through server app
6. Paste that generated token client side ...there will be function to add token in agent app

Important Note : only use one token per client/machine/agent
Important : create a readonly mongo user , there is a file "create_mongo_read_user.txt" , mongo client in agent application is in lib_shared/common_config.py 

6. Now in client side... In prava.conf change server address to the hosted server machine
7. In prava.conf , change log files paths as you want 


---------------------Features Down Below---------------------
8. Hence your logs are getting transferred from client to server , traffic analysis compares the malicious url,domain,ip and sends alert to server and also alerts get store in mongodb
9. Malicious traffic pcap file also goes to server.
10. resource monitor added , sends alerts if resource get used above threshold value
11. Security Policies functions added too
12. Yara rules get synchronized from server to clients by -sync option in prava_agent app
