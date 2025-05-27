<!-- GETTING STARTED -->
## Getting Started

This automated, dynamic analysis Android tool uncovers discrepancies and inconsistencies between 
[Data Safety Section](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en)
labels and the Applications' run-time behaviour.

### Prerequisites

* Rooted Android 13 (API 33) or higher
* python3 or higher
* Frida 16.2.1 (server & client)
* Burp Suite Community Edition v2025.4.4
* OpenSSL 1.1.1f

### Set Up

* *UIHarvester*:
  
  1. adb install -g ./Services/UIHarvesterService.apk
  2. Go to "Settings"
  3. Press "Accessibility"
  4. In "UIHarvesterService" section. Toggle the button to "On"
* *Frida*:
  
  ```sh
  pip install frida-tools
  ```
  * Download [frida-server-16.2.1-android-arm64.xz](https://github.com/frida/frida/releases/download/16.2.1/frida-server-16.2.1-android-arm64.xz)
  * Extract the file
  ```sh
  mv <file_name> frida-server
  adb push frida-server data/tmp/local
  chmod +x data/tmp/local/frida-server
  ```
* *Proxy*:
  1. Go to "Settings"
  2. Go to "Network & Internet"
  3. Press the "settings button image" in your Wi-Fi connection 
  4. Go to "Proxy"
  5. Select "Manual"
  6. Type your computer's IP as "Proxy hostname" and as the port the "8080"

* *Burp*:
  1. Go to "Proxy"
  2. Go to "Proxy Settings"
  3. Edit the listener to listen to your Android Device or "All interfaces"
  4. Press "Import/Export CA certificate"
  5. Press "Certificate in DER format" in the Export section
  6. Press "Next"
  7. Select the file "./burp_certificate_inject/burp.der" to save it
  
<!-- USAGE EXAMPLES -->
## Usage

python3 run.py --list <LIST_OF_APPS> --country <COUNTRY_CODE>

Example:
```sh
python3 run.py --list apps.txt --country gr
```

