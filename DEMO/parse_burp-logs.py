import xml.etree.ElementTree as ET
import json
import os
import re
import base64
import sys

apk = sys.argv[1]

output_hosts = "./burp-decoded-clean/hostnames"

keywords = {
    "43f4dcd1-dc4e-4070-96e7-5a6fc1dce08b": "AdvertisingID", 
    "349ca25382972d16": "Android_Device_ID",
    "96153f466b1cb25c": "DeviceID",
    "3b1672794f9c6aa6": "Google_Services_Framework_ID",
    "dummyjordan33@gmail.com": "Email",
    "dummy": "Name",
    "jordan": "Surname",
    "feb 1, 1990": "Birthday",
    "01-02-1990": "Birthday",
    "02-01-1990": "Birthday",
    "01/02/1990": "Birthday",
    "02/01/1990": "Birthday",
    "rather not say": "Gender",
    "athens": "Address",
    "f8:0f:f9:da:2c:24": "Bluetooth_Address",
    "16091JEC203869": "Android_Serial_Number",
    "VODAFONE_H268Q-0611": "SSID",
    "e0:b6:68:9b:94:d1": "BSSID",
    "f8:0f:f9:da:2c:25": "MACaddr",
    "359606774638960": "IMEI",
    "89049032000001000000043953979256": "EID",
    "pixel 4a": "DeviceName",
    "tq3a.230805.001.s1": "BuildNumber",
    "jordangarciahernandes663": "ContactName",
    "6996959394": "ContactNumber",
    "37.988": "Latitude",
    "23.680": "Longitude",
}


hosts = {}

def remove_unicode_sequences(s):
    # Remove Unicode escape sequences of the form \uXXXX
    s = re.sub(r'\\u[0-9a-fA-F]{4}', '', s)
    # Remove Unicode escape sequences of the form \u00XX
    s = re.sub(r'\\u00[a-fA-F0-9]{2}', '', s)
    return s

def process_request(request):
    try:
        # Decode from Base64
        decoded_bytes = base64.b64decode(request)
        # Decode using Latin-1
        decoded_string = decoded_bytes.decode('latin-1')
        # Remove Unicode escape sequences
        clean_string = remove_unicode_sequences(decoded_string)
        # Check if the resulting string is valid JSON
        # json.loads(clean_string)
        # If parsing succeeds, the string is valid JSON
        return clean_string
    except Exception as e:
        # Handle decoding errors or invalid JSON
        print(f"Error processing request: {e}")
        return None

for filename in os.listdir("burp_logs"):

    if apk+".json" != filename:
        continue

    tree = ET.parse(os.path.join("burp_logs", filename))
    root = tree.getroot()

    data_shared = []

    # output_filename = os.path.join("burp-decoded-clean/"+filename+".json")

    if not os.path.exists("burp-decoded-clean/"+filename):
        with open("burp-decoded-clean/"+filename, 'w') as json_file:
            json_file.write('')

    flow_data_list = []
    items = root.findall("./item")
    for item in items:
        request_data = None
        host = item.find('host')
        host_ip = host.attrib['ip']
        full_host  = host.text
        request = item.find("request").text 
        response = item.find("response").text
        comment = item.find('comment').text
        port = item.find('port').text
        request_content = None
        
        response_content = None
        
        if request is not None:
            try:
                request_content = process_request(request)
            except json.decoder.JSONDecodeError:
                print("test fail")
                request_content = {}

        if response is not None:
            try:
                response_content = process_request(response)
                
            except json.decoder.JSONDecodeError:
                print("test fail")
                response_content = {}
        
        if request_content is not None or response_content is not None:
            keywords_data = []
            for item in keywords:
                if item in request_content:
                    keywords_data.append(item)
                    data_shared.append(keywords[item])

            jsonobj = {
                "full_host" : full_host,
                "ip" : host_ip,
                "port": port,
                "req": request_content,
                "res" : response_content,
                "keywords" : keywords_data
            }
            flow_data_list.append(jsonobj)
    # print((flow_data_list))
    with open("burp-decoded-clean/"+filename, 'w') as json_file:
        json.dump(flow_data_list, json_file, indent=4)

    with open("shared_data_results/"+filename, 'w') as json_file:
        json.dump(list(set(data_shared)), json_file, indent=4)
    


print("Hosts data has been written to", output_hosts)
