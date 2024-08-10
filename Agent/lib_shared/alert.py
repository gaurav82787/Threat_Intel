import requests
from datetime import datetime
def send_alert(url, category, message, severity, description,token):
    # Prepare the payload with current date and time
    payload = {
        'date_time': datetime.now().isoformat(),  # ISO format date & time
        'category': category,
        'message': message,
        'severity': severity,
        'description': description,
        'token' : token
    }
    
    try:
        # Send the POST request
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        response.raise_for_status()
        
        # Print or log the response
        print(f"Alert sent successfully: {response.status_code}")
        print(f"Response: {response.text}")
        
    except requests.exceptions.RequestException as e:
        # Handle any errors that occur during the request
        print(f"Error sending alert: {e}")

