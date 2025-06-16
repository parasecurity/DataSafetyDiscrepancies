from google_play_scraper.exceptions import NotFoundError, ExtraHTTPError
from google_play_scraper.features.data_safety import data_safety
from google_play_scraper.features.permissions import permissions
from google_play_scraper_master.google_play_scraper.scraper import PlayStoreScraper
import os
import multiprocessing
import argparse
import time
import json
import subprocess

parser = argparse.ArgumentParser(
                    prog='Play Store Crawler',
                    description='Crawl details for apps from Play Store')
parser.add_argument('--list', dest='list', type=ascii,
                    help='The name of file with all package names')
parser.add_argument('--country', dest='country', type=ascii, default='gr',
                    help='The country code of the country for crawling')


args = parser.parse_args()

lst_name = args.list.replace("'","")
country = args.country.replace("'","")

#saved_apps_dir = "<your_folder>/"
saved_apps_dir = "/home/arkalos/Documents/ANDROID/Android/GooglePlay_downloader/lala"

#############################
serialnum = "16091JEC203869"
#############################

os.system("scrcpy &")
time.sleep(2)

scraper = PlayStoreScraper()

# os.system("adb shell 'su -c ./data/local/tmp/frida-server &' &")
os.system("sh add_certificate.sh")

def download(line):
    apk = line.strip()

    try:

        try:
            details = scraper.get_app_details(apk, country=country, lang="en_us")
        except:
            print("ERROR: "+apk);
            return

        perms = permissions(
            apk,
            lang='en', # defaults to 'en'
            country=country # defaults to 'us'
        )

        dataSafety = data_safety(
            apk,
            lang='en', # defaults to 'en'
            country=country # defaults to 'us'
        )     

        item_info = {
            "package_name": apk,
            "details": details,
            "perms": perms,
            "data_safety": dataSafety
        }

        with open("dss/"+apk+".json", 'w') as json_file:
            json.dump(item_info, json_file, indent=4)

    except (NotFoundError, ExtraHTTPError):
        print(f"ERROR: Not found app '{apk}'");


    # os.system(f"adb shell am start -a android.intent.action.VIEW -d 'market://details?id={apk}'")
    # time.sleep(2)
    # os.system("adb shell input tap 540 920")

    ######Download the app#########
    try:
        error=os.popen(f"java -Draccoon.homedir={saved_apps_dir} -Draccoon.home={saved_apps_dir}/apps/ -jar raccoon4.jar --gpa-download {apk}").read().replace("\n","")
        if error=="!fail.Item not found.!":
            print(f"Error: app with package name {apk} not found in PlayStore.")
        elif "DF-DFERH-" in error:
            print(f"Error: app with package name {apk} not downloaded.")
        print(error)
    except e:
        print("exception")

def play(line):
    apk = line.strip()

    os.system("rm -rf ./execution_wrapper/APPS/*")
    os.system(f"cp -r {saved_apps_dir}/apps/content/apps/{apk} execution_wrapper/APPS/{apk}")

    # process = subprocess.run(["python3", "main.py", "-p", "APPS", "-m", "auto", "-r", "1"], cwd="execution_wrapper")

    inpt = input("Press a button to continue...")

    os.system(f"python3 parse_burp-logs.py {apk}")

    print("\n\nData Safety Section Results:\n")
    print("############################")
    os.system(f"python3 dss_discrepancies.py {apk}")
    print("############################")

    pids = os.popen("ps -aux | grep scrcpy | awk '{print $2}'").read()

    for pid in pids.split("\n")[:-1]:
        os.system(f"kill -9 {pid}")
        break

    os.system("scrcpy &")
    time.sleep(2)

with open(lst_name) as f:
    for line in f:
        download(line)

with open(lst_name) as f:
    for line in f:
        play(line)

    pids = os.popen("ps -aux | grep scrcpy | awk '{print $2}'").read()

    for pid in pids.split("\n")[:-1]:
        os.system(f"kill -9 {pid}")
        break
