import requests
import json
import os
import datetime

class NordpassRequest (object):
    def __init__(self):
        pass

    def get_wordlist(self):
        # Request the password list from NordPass
        headers = {
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'Referer': 'https://nordpass.com/most-common-passwords-list/',
            'sec-ch-ua-mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'sec-ch-ua-platform': '"Windows"',
        }
        response = requests.get('https://nordpass.com/json-data/top-worst-passwords/findings/all.json', headers=headers)

        #print(response.text)

        # Convert the response to a JSON object
        json_object = json.dumps(response.json())

        # Write the JSON object to a file
        try: 
            with open(os.getcwd() + "/data/nordpass_wordlist.json", "w") as outfile:
                outfile.write(json_object)

            print("Wordlist downloaded from NordPass " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        except:
            print("Error Wordlist writing to file")
        
        
