import json
import sys
import os

mapping = {
	"android.accounts.AccountManager.addAccount": ["Personal info"],
	"android.accounts.AccountManager.getAccounts": ["Personal info"],
	"android.accounts.AccountManager.getAccountsByType": ["Personal info"],
	"android.accounts.AccountManager.getAccountsByTypeAndFeatures": ["Personal info"],
	"android.accounts.AccountManager.getAccountsByTypeForPackage": ["Personal info"],
	"android.accounts.AccountManager.getAuthToken": ["Personal info"],
	"android.accounts.AccountManager.getPassword": ["Personal info"],
	"android.accounts.AccountManager.getPreviousName": ["Personal info"],
	"android.accounts.AccountManager.getUserData": ["Personal info"],
	"android.accounts.AccountManager.setPassword": ["Personal info"],
	"android.accounts.AccountManager.setUserData": ["Personal info"],
	"android.app.ActivityManager.getRecentTasks": ["App activity"],
	"android.app.ActivityManager.getRunningAppProcesses": ["App activity"],
	"android.app.ActivityManager.getRunningTasks": ["App activity"],
	"android.app.AppOpsManager.startWatchingMode": ["App info and performance", "Diagnostics"],
	"android.app.AppOpsManager.startWatchingStarted": ["App info and performance", "Diagnostics"],
	"android.app.usage.UsageStatsManager.getAppStandbyBucket": ["App info and performance"],
	"android.app.WallpaperManager.getDrawable": ["Photos or videos", "Photos", "Files and docs"],
	"android.bluetooth.BluetoothA2dp.getConnectedDevices": ["Device or other IDs"],
	"android.bluetooth.BluetoothA2dp.getDevicesMatchingConnectionStates": ["Device or other IDs"],
	"android.bluetooth.BluetoothAdapter.getAddress": ["Device or other IDs"],
	"android.bluetooth.BluetoothAdapter.getBondedDevices": ["Device or other IDs"],
	"android.bluetooth.BluetoothAdapter.getName": ["Device or other IDs"],
	"android.bluetooth.BluetoothDevice.getName": ["Device or other IDs"],
	"android.bluetooth.BluetoothDevice.getType": ["Device or other IDs"],
	"android.bluetooth.BluetoothDevice.getUuids": ["Device or other IDs"],
	"android.bluetooth.BluetoothHeadset.getConnectedDevices": ["Device or other IDs"],
	"android.bluetooth.BluetoothHearingAid.getDevicesMatchingConnectionStates": ["Device or other IDs"],
	"android.bluetooth.BluetoothManager.getConnectedDevices": ["Device or other IDs"],
	"android.bluetooth.BluetoothManager.getDevicesMatchingConnectionStates": ["Device or other IDs"],
	"android.content.ContentProvider.openAssetFile": ["Files and docs"],
	"android.content.ContentProvider.openTypedAssetFile": ["Files and docs"],
	"android.content.ContentResolver.query": ["Device or other IDs"],
	"android.location.LocationManager.addGpsStatusListener": ["Location", "Precise location"],
	"android.location.LocationManager.addNmeaListener": ["Location", "Precise location"],
	"android.location.LocationManager.getCurrentLocation": ["Location", "Precise location", "Approximate location"],
	"android.location.LocationManager.getLastKnownLocation": ["Location", "Precise location", "Approximate location"],
	"android.location.LocationManager.registerGnssStatusCallback": ["Location", "Precise location"],
	"android.location.LocationManager.requestLocationUpdates": ["Location", "Precise location", "Approximate location"],
	"android.location.LocationManager.requestSingleUpdate": ["Location", "Precise location", "Approximate location"],
	"android.media.RingtoneManager.getRingtone": ["App info and performance", "Diagnostics"],
	"android.net.wifi.WifiInfo.getBSSID": ["Device or other IDs"],
	"android.net.wifi.WifiInfo.getSSID": ["Device or other IDs"],
	"android.os.BatteryManager.getLongProperty": ["App info and performance", "Diagnostics"],
	"android.os.Build.getSerial": ["Device or other IDs"],
	"android.os.Debug.getMemoryInfo": ["App info and performance", "Diagnostics"],
	"android.os.Debug.getNativeHeapAllocatedSize": ["App info and performance", "Diagnostics"],
	"android.os.Debug.getNativeHeapFreeSize": ["App info and performance", "Diagnostics"],
	"android.os.Debug.getNativeHeapSize": ["App info and performance", "Diagnostics"],
	"android.os.Debug.getRuntimeStat": ["App info and performance", "Diagnostics"],
	"android.os.health.HealthStats.getMeasurement": ["App info and performance", "Diagnostics"],
	"android.os.health.HealthStats.getStats": ["App info and performance", "Diagnostics"],
	"android.os.PowerManager.getCurrentThermalStatus": ["App info and performance", "Diagnostics"],
	"android.os.StrictMode.getThreadPolicy": ["App info and performance"],
	"android.os.StrictMode.getVmPolicy": ["App info and performance"],
	"android.telecom.TelecomManager.getCallCapablePhoneAccounts": ["Personal info"],
	"android.telecom.TelecomManager.getDefaultOutgoingPhoneAccount": ["Contacts"],
	"android.telecom.TelecomManager.isVoiceMailNumber": ["Personal info", "Phone number"],
	"android.telephony.PhoneNumberUtils.isVoiceMailNumber": ["Personal info", "Phone number"],
	"android.telephony.PhoneStateListener.onCellInfoChanged": ["Location", "Precise location"],
	"android.telephony.PhoneStateListener.onCellLocationChanged": ["Location", "Precise location"],
	"android.telephony.SubscriptionInfo.getIccId": ["Device or other IDs"],
	"android.telephony.SubscriptionManager.getActiveSubscriptionInfo": ["Personal info"],
	"android.telephony.SubscriptionManager.getActiveSubscriptionInfoForSimSlotIndex": ["Personal info"],
	"android.telephony.SubscriptionManager.getActiveSubscriptionInfoList": ["Personal info"],
	"android.telephony.TelephonyManager.getAllCellInfo": ["Location", "Precise location"],
	"android.telephony.TelephonyManager.getCardIdForDefaultEuicc": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getCellLocation": ["Location", "Precise location"],
	"android.telephony.TelephonyManager.getDataNetworkType": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getDeviceId": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getDeviceSoftwareVersion": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getGroupIdLevel1": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getImei": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getLine1Number": ["Personal info", "Phone number"],
	"android.telephony.TelephonyManager.getMeid": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getNeighboringCellInfo": ["Location", "Approximate location"],
	"android.telephony.TelephonyManager.getNetworkCountryIso": ["Personal info"],
	"android.telephony.TelephonyManager.getNetworkOperator": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getNetworkOperatorName": ["Personal info"],
	"android.telephony.TelephonyManager.getPhoneCount": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getServiceState": ["Location", "Approximate location"],
	"android.telephony.TelephonyManager.getSimSerialNumber": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getSimSpecificCarrierId": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getSubscriberId": ["Device or other IDs"],
	"android.telephony.TelephonyManager.getVisualVoicemailPackageName": ["App activity"],
	"android.telephony.TelephonyManager.getVoiceMailNumber": ["Personal info", "Phone number"],
	"android.telephony.TelephonyManager.getVoiceNetworkType": ["Device or other IDs"],
	"android.telephony.TelephonyManager.requestCellInfoUpdate": ["Location", "Precise location"],
	"java.io.File.getFreeSpace": ["App info and performance", "Other app performance data"],
	"java.io.File.getTotalSpace": ["App info and performance", "Other app performance data"],
	"java.io.File.getUsableSpace": ["App info and performance", "Other app performance data"],
	"java.net.NetworkInterface.getHardwareAddress": ["Device or other IDs"],
	"AdvertisingID": ["Device or other IDs"],
	"Android_Device_ID": ["Device or other IDs"],
	"DeviceID": ["Device or other IDs"],
	"Google_Services_Framework_ID": ["Device or other IDs"],
	"Email": ["Personal info", "Email address "],
	"Name": ["Personal info", "Name"],
	"Surname": ["Personal info", "Name"],
	"Birthday": ["Personal info", "Other info"],
	"Gender": ["Personal info", "Other info"],
	"Address": ["Personal info", "Other info", "Location", "Approximate location"],
	"Bluetooth Address": ["Device or other IDs"],
	"Android Serial Number": ["Device or other IDs"],
	"SSID": ["Device or other IDs"],
	"BSSID": ["Device or other IDs"],
	"MACaddr": ["Device or other IDs"],
	"IMEI": ["Device or other IDs"],
	"EID": ["Device or other IDs"],
	"DeviceName": ["Device or other IDs"],
	"BuildNumber": ["Device or other IDs"],
	"ContactName": ["Contacts"],
	"ContactNumber": ["Contacts"],
	"Latitude": ["Location", "Approximate location", "Precise location"],
	"Longitude": ["Location", "Approximate location", "Precise location"]
}

apk = sys.argv[1]


dss_shared = []

with open("dss/"+apk+".json", 'r') as json_file:
    data = json.load(json_file)
    if "data_safety" in data and "dataShared" in data["data_safety"]:
        if data["data_safety"]["dataShared"] != None:
            for label in data["data_safety"]["dataShared"]:
                if data["data_safety"]["dataShared"][label] != None:
                    for item in data["data_safety"]["dataShared"][label]:
                        dss_shared.append(item["name"])
                dss_shared.append(label)


dss_collected = []

with open("dss/"+apk+".json", 'r') as json_file:
    data = json.load(json_file)
    if "data_safety" in data and "dataCollected" in data["data_safety"]:
        if data["data_safety"]["dataCollected"] != None:
            for label in data["data_safety"]["dataCollected"]:
                if data["data_safety"]["dataCollected"][label] != None:
                    for item in data["data_safety"]["dataCollected"][label]:
                        dss_collected.append(item["name"])
                dss_collected.append(label)

collected_tmp = []
collected = []
with open(f"./results/{apk}/frida/logfile", 'r') as f:
	for line in f:
		if "@@@Method@@@:" in line:
			collected_tmp.append(line.replace("@@@Method@@@:","").replace("\n",""))

shared_tmp=[]
shared = []
with open("shared_data_results/"+apk+".json", 'r') as json_file:
	shared_tmp = json.load(json_file)

for item in collected_tmp:
	for i in mapping[item]:
		collected.append(i)

for item in shared_tmp:
	for i in mapping[item]:
		shared.append(i)

final_collected = []
for item in collected:
	if item in dss_collected:
		final_collected.append(item)

final_shared = []
for item in shared:
	if item in dss_shared:
		final_shared.append(item)

print("Collected Discrepancies:", "{}" if set(collected)-set(dss_collected) == set() else set(collected)-set(dss_collected))
print("Shared Discrepancies:", "{}" if set(shared)-set(dss_shared) == set() else set(shared)-set(dss_shared))


funcs = []
for item in set(collected)-set(dss_collected):
	for key,value in mapping.items():
		if item in value and ("android." in key or "java." in key):
			funcs.append(key)

os.system(f"python3 parsefridaJan.py {apk}")

func_origin = os.popen(f"python3 origin_extractor.py {apk}").read()

core_origin = 0
third_party_origin = 0
functions_counter = 0

for item in func_origin.split("\n")[:-1]:
	func = item.split(";")[0]
	if func in set(funcs):
		functions_counter+=1
		if item.split(";")[1].strip().replace("\n","") in apk or item.split(";")[1].strip().replace("\n","") == "Core-Origin":
			core_origin +=1
			print(item)
		else:
			third_party_origin +=1
			print(item)

if functions_counter==0:
	functions_counter=1
	core_origin=0
	third_party_origin=0

print("Core Discrepancies:",str(format(core_origin/functions_counter*100, ".2f"))+"%","\nThird-Party Discrepancies:", str(format(third_party_origin/functions_counter*100, ".2f")+"%"))
