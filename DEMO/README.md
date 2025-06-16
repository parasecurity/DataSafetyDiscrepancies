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
* Raccoon 4.24.0
* DummyDroid  3.0
* scrcpy

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

* *Raccoon*:

  A. Open DummyDroid `java -jar dummydroid-3.0.jar`
  1. Fill the fields in DummyDroid `java -jar dummydroid-3.0.jar`: 
  * Model
  ```sh
      adb shell getprop ro.product.model
  ```
  * Manufacturer
  ```sh
      adb shell getprop ro.product.manufacturer
  ```
  * Brand
  ```sh
     adb shell getprop ro.product.brand 
  ```
  * Product
  ```sh
      adb shell getprop ro.product.name
  ```
  * Device
  ```sh
      adb shell getprop ro.product.device
  ```
  * Hardware
  ```sh
      adb shell getprop ro.hardware
  ```
  * Id
  ```sh
      adb shell getprop ro.product.id
  ```
  or
  ```sh
      adb shell getprop ro.build.id
  ```
  * Release version
  ```sh
      adb shell getprop ro.build.version.release
  ```
  * Fingerprint
  ```sh
      adb shell getprop ro.build.fingerprint 
  ```

      
  2. Enter Google account credentials in Uplink Terminal
  * Click Login account

  * If log says "Failure To access your account, you must sign in on the web."

      -Copy paste the url of the above message in your browser and login (we need to insert the oauth token to dummydroid - needs to be done quickly)

      -Open Console - Storage - Cookies and find oauthtoken. Copy the value (you may have two values check which one works with the following steps)

      -Paste the value in Dummydroid under Uplink-->Web login flow

      -Click Login account. Succesfull login wll show the values (save them as they are needed for the Raccoon profile)

        Account: ...
        Name: ...
        Email: ...
        Auth Token: ...
        Services:...
    
    (More info in https://raccoon.onyxbits.de/blog/needs-browser-login-workaround/)

  * Click Register GSF ID. Succesfull registration will show the values: (save them as they are needed for the Raccoon profile)
      GSF ID: ...
      User Agent: ...

  3. Store the above values and close DummyDroid

  B. Get the GSF ID (we need the GSF ID of the device, not the one provided by Raccoon)
  * For rooted device 
      ```sh
      adb shell
      ```
      ```sh
      su
      cp /data/data/com.google.android.gsf/databases/gservices.db /sdcard/Download
      ```
      ```sh
      adb pull /sdcard/Download/gservices.db .
      printf '%x\n' $(sqlite3 gservices.db "select * from main where name = \"android_id\";" | cut -d'|' -f2)
      ```
  C. Open Raccoon and set the directory to save the apps

  ```sh
      java -Draccoon.homedir=<your_folder> -Draccoon.home=<your_folder>/apps/ -jar raccoon4.jar
  ```
      
  * Login with your Gmail Credentials
      
  * If Raccoon says "NeedsBrowser"

     -Close Raccoon

     -Edit /apps/content/database/raccoondb_4.script

     -Append the following 2 lines in the raccoondb_4.script

  ```
  INSERT INTO PLAYPROFILES VALUES('test_account','test_account@gmail.com','test_Auth_Token','test_User_Agent',NULL,0,NULL,NULL,'test_GSFID','test_password')
  ```

  ```
  INSERT INTO VARIABLES VALUES('playprofile','test_account')
  ```
  Example Gmail account creds to be used in the above lines in the raccoon database:

      email: test_account@gmail.com
      password: test_password
      Auth Token: test_Auth_Token (get from step A.2)
      User Agent: test_User_Agent (get from step A.2)
      GSF ID : test_GSFID (get from step B)

  * Download an app using the Raccoon program to test if everything works

  * Notes:
      - The apks are downloaded inside ./apps/content/apps/
      - Multiple apks may exists inside each packagename folder. Install each Android application using adb install-multiple *.apk
<!-- USAGE EXAMPLES -->
## Usage

python3 run.py --list <LIST_OF_APPS> --country <COUNTRY_CODE>

Example:
```sh
python3 run.py --list apps.txt --country gr
```

