import json

dss_shared = []
with open("dss/"+"pl.lifebite.iyoni"+".json", 'r') as json_file:
    data = json.load(json_file)
    if "data_safety" in data and "dataCollected" in data["data_safety"]:
        if data["data_safety"]["dataCollected"] != None:
            for label in data["data_safety"]["dataCollected"]:
                if data["data_safety"]["dataCollected"][label] != None:
                    for item in data["data_safety"]["dataCollected"][label]:
                        dss_shared.append(item["name"])
                dss_shared.append(label)

for i in set(dss_shared):
    print(i)
