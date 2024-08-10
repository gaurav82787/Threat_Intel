import requests
import re
import random
from .static import *
from datetime import datetime
import pymongo
def init_feeds():
    if "feeds" not in p_db.list_collection_names():
        p_db.create_collection("feeds")
        print("Initialized feeds collection.")
    for item in feed_types:
        # Create the collection for each feed type if it doesn't exist
        if item not in db.list_collection_names():
            db.create_collection(item)
            print(f"Initialized collection for {item}.")
        CTI_item = "CTI_" + item
        if CTI_item not in db.list_collection_names():
            db.create_collection(CTI_item)
            print(f"Initialized collection for {CTI_item}.")   
        
def update_feed():
    init_feeds()
    feeds_collection = p_db["feeds"]
    rows = feeds_collection.find()
    for item in rows:
        try:
            raw_url = item["feed_url"].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            user_agent = random.choice(spoofed_user_agents)
            headers = {'User-Agent': user_agent}
            response = requests.get(raw_url, headers=headers)
            content = response.text
            
            if response.status_code == 200:
                feed_collection = db[item["feed_type"]]
                if item["feed_type"] == "mal_ip":
                    content = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
                elif item["feed_type"] == "mal_domain":
                    pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b|\b[a-zA-Z0-9-_]+\b'
                    content = re.findall(pattern, content)
                elif item["feed_type"]=="mal_url":
                     content = re.findall(r'\b(?:https?:\/\/)?(?:[a-zA-Z0-9-]+\.)*(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?:\/[^\s]*)?\b|(?:https?:\/\/)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{2,5})?(?:\/[^\s]*)?\b',content)
                else:
                    content = []
                if not content:
                    print(f"[-] Error Fetching Data in {item['feed_url']}")
                else:
                    existing_data = [doc[item['feed_type']] for doc in feed_collection.find(filter={'Source':item['feed_url']})]
                    added_data = set(content) - set(existing_data)
                    removed_data = set(existing_data) - set(content)
                    if not added_data and not removed_data:
                        print(f"[*] No Update in {item['feed_type']} from Source - {item['feed_url']}")
                    else:
                        print(f"[<] In {item['feed_type']} from {item['feed_url']}\n[+] To be Added - {len(added_data)} item(s)\n[-] To be Removed - {len(removed_data)} item(s)")
                        feed_collection.delete_many(filter = { 'Source': item['feed_url'] } )
                        feed_collection.insert_many([{'Source':item['feed_url'], item['feed_type']: value} for value in content])
                        print(f"[>] Updated Successfully from Source {item['feed_url']}")     
            else:
                print(f"{item['feed_url']} not Reachable")
        except Exception as e:
            print(f"Error Occurred in {item['feed_url']}: {e}")
    for item in feed_types:
        CTI_item = "CTI_" + item
        collection= db[item]
        collection2 = db[CTI_item]
        # rows = collection.find()
        #pipeline to find duplicate values like mal_ip and merging every repeated ip into one and adding source_url as url1,url2,etc this will help in analyzing the data fastly 
        #new collection then will named as CTI_<feed_type> , when implementing the threat data we will use this kind of named collection
        pipeline = [

        {
    "$match": {
        "Source": {"$exists": True, "$ne": ""},
        f"{item}": {"$exists": True, "$ne": ""}
    }
},
{
    "$group": {
        "_id": f"${item}",
        "sources": {"$addToSet": "$Source"}
    }
},
{
    "$addFields": {
        "source": {
            "$reduce": {
                "input": "$sources",
                "initialValue": "",
                "in": {
                    "$concat": [
                        {"$cond": [{"$eq": ["$$value", ""]}, "", {"$concat": ["$$value", ", "]}]},
                        "$$this"
                    ]
                }
            }
        }
    }
},
{
    "$project": {
        "_id": 0,
        f"{item}": "$_id",
        "source": 1
    }
}
]
        result = list(collection.aggregate(pipeline))
        if result != []:
            collection2.delete_many({})
            collection2.insert_many(result)
        else:
            print(f"[*] CTI_{item} is not Populated")
            

def add_feed(feed_type, feed_url):
    init_feeds()
    if feed_type not in feed_types:
        print("Feed Type Not Found")
    else:
        feeds_collection = p_db["feeds"]
        feeds_collection.insert_one({"feed_type": feed_type, "feed_url": feed_url})
        print(f"Feed {feed_type} with URL {feed_url} added successfully.")

def Restrict_IP(ip,message):
    if "Restricted_IP" not in db.list_collection_names():
        db.create_collection("Restricted_IP")
    ip_pattern= r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    if re.fullmatch(ip_pattern, ip):
        ban_ip = db["Restricted_IP"]
        dupl = ban_ip.find_one({"IP":ip})
        if dupl:
            print("IP is Already in Restricted Data")
        else:
            ban_ip.insert_one({'Date_Time':datetime.now().isoformat(), 'IP': ip,'message':message})
            print("Added Successfully")
    else:
        print("Enter Valid IP address")

def Restricted_Directories(dir):
    # Define patterns as raw strings directly
    windows_pattern = r'^[a-zA-Z]:\\(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]*$'
    linux_pattern = r'^(/[^<>:"/\\|?*\r\n]+)*(/[^<>:"/\\|?*\r\n]*)?$'
    os_type=""
    # Check against Windows pattern
    if re.fullmatch(windows_pattern, dir):
        os_type="Windows"
    # Check against Linux pattern
    if re.fullmatch(linux_pattern, dir):
        os_type="Linux"
    if os_type=="":
        print("Enter a Valid Path and Note Windows use \'\\\' instead of \'/\' which is used in Linux.")
    else:
        dir_collection=db["Restricted_Directories"]
        dupl = dir_collection.find_one({'directory':dir})
        if dupl:
            print("Directory is Already in Restricted Data")
        else:
            dir_collection.insert_one({'directory':dir,'os':os_type})
            print("Directory Added Successfully")

def show_restricted_ip():
    ban_ip = db["Restricted_IP"]
    ban_ip = ban_ip.find()
    for item in ban_ip:
        print(f'{item["IP"]} : Info - {item["message"]}')

def show_restricted_directories():
    dir_collection=db["Restricted_Directories"]
    dir_collection=dir_collection.find().sort("os", pymongo.ASCENDING)
    for item in dir_collection:
            print(item["directory"])
def add_api_feed(url,api):
    print(url)
    print(api)

if __name__== "__main__":
    # Restrict_IP("10.10.1.120","through test function")
    # Restricted_Directories("C:\\Program Files")
    pass