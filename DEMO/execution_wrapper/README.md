# Android Application Wrapper

## Overview
This project provides a framework for monitoring an Android device, managing Frida server interactions, and running traversing or manual modes for application testing. It integrates several components to ensure the health of the device and the stability of the testing environment. The primary classes and their functionalities include:

- **ADBMonitor**: Monitors ADB (Android Debug Bridge) connectivity.
- **FridaMonitor**: Checks the status of the Frida server and ensures it is running.Tests are available.
- **DeviceStatus**: Monitors the status of the Android device.
- **ManualMode**: (WIP) Manages manual application testing and interaction with Frida scripts.
- **TraversingMode**: Handles automated application traversal, including retries on failure.
- **ApplicationRunner**: The main runner class that coordinates the monitoring and testing processes.

## Requirements:
* Python > 3.*
* Android Debug Bridge (adb)
* Frida toolkit

## Install requirements
``` 
pip install requirements.txt
```
## Set up Frida 
* Push Frida Server to the device
* Optional: Start Frida Server(default port) or Frida starts at port 12345.


## Start the execution wrapper
### Monitor and execute applications in android device or emulator.
#### Parameters 
* -p : Specifies the path to the directory that contains one or more folders, each of which includes APK file(s).
```
./apps
├── com.bettertogether.us
    └── com.bettertogether.us-433.apk
├── com.kept.triaxiom
    ├── com.kept.triaxiom-143.apk
    ├── config.arm64_v8a-143.apk
    ├── config.el-143.apk
    ├── config.en-143.apk
    └── config.xxhdpi-143.apk
```
* -m : Selects the execution mode. Available options are auto (either Traversing or RecordNReplay) or manual (functionality to be implemented).
* -r : Specifies the maximum number of retries allowed per application execution.
  ```
  python3 main.py -p /path/to/apks -m auto -r 3
  ```
* -retryFailedApps : Re-analyzes the apps that have not been succesfully traversed and are logged in traversal_status.json.
* Check main.py --help for options

#### Extras
* Traversing Options: Modify the source code of [mode.py](https://github.com/Michalis-Diamantaris/Android/blob/main/UIHarvester/AccessibilityService/execution_wrapper/application_runner/mode.py) to adjust the traversing options. Refer to the [Traversing section](https://github.com/Michalis-Diamantaris/Android/blob/main/UIHarvester/AccessibilityService/readme.md) for more detailed information.

* Frida Port: To change the listening port of the frida-server, edit the [frida_monitor.py](https://github.com/Michalis-Diamantaris/Android/blob/main/UIHarvester/AccessibilityService/execution_wrapper/maid/frida_monitor.py).

## Examples
* Auto-example
Iterate over a folder with apks, traverse each application, with 3 maximum attempts of failure.

```
python3 main.py -p /apps/ -m auto -r 3
```

## Logfiles
Main logfile for identifying succesfull/unsuccesfull apps can be found at [traversal_status.json](https://github.com/Michalis-Diamantaris/Android/blob/main/UIHarvester/AccessibilityService/execution_wrapper/traversal_status.json)

```
{
    "com.imdb.mobile": {
        "attempts": [
            {
                "start_timestamp": "2024-10-03 15:14:27",
                "end_timestamp": "2024-10-03 15:14:35",
                "status": false,
                "message": "Frida failed."
            },
            {
                "start_timestamp": "2024-10-03 15:16:04",
                "end_timestamp": "2024-10-03 15:16:13",
                "status": false,
                "message": "Boot sequence is not yet completed."
            },
            {
                "start_timestamp": "2024-10-03 15:17:19",
                "end_timestamp": "2024-10-03 15:18:32",
                "status": true
            }
        ],
        "status": true
    }
}
```
(successful/unsuccessful ==> status: true/false).

**!!!Important!!!**

App package names written in [traversal_status.json](https://github.com/Michalis-Diamantaris/Android/blob/main/UIHarvester/AccessibilityService/execution_wrapper/traversal_status.json) will **NOT** be re-analyzed by running main.py again independent of their status

Check option -retryFailedApps for applications that have not been traversed. 

Debugging logs are located at [application_runner.log](https://github.com/Michalis-Diamantaris/Android/blob/main/UIHarvester/AccessibilityService/execution_wrapper/logs/application_runner.log), [traversing.log](https://github.com/Michalis-Diamantaris/Android/blob/main/UIHarvester/AccessibilityService/execution_wrapper/logs/traversing.log) and [unsuccessful_traversals.log](https://github.com/Michalis-Diamantaris/Android/blob/main/UIHarvester/AccessibilityService/execution_wrapper/logs/unsuccessful_traversals.log).


## Troubleshooting

* Manual execution is not implemented yet.
* In case of broken frida pipes or adbd failure, restarting the device is recommended.
## Testbeds
* Android Device: Pixel 6 - Android version 14, Pixel 4 - Android version 13 
* frida: frida-server v16.2.1, frida-server v16.5.1 
* adb: Android Debug Bridge version 1.0.41 Version 35.0.1-11580240
