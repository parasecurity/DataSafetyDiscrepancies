from google_play_scraper.exceptions import NotFoundError, ExtraHTTPError
from google_play_scraper.features.data_safety import data_safety
from google_play_scraper.features.permissions import permissions
from google_play_scraper_master.google_play_scraper.scraper import PlayStoreScraper
import os
import multiprocessing
import argparse
import time
import json

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

#############################
serialnum = "16091JEC203869"
#############################


scraper = PlayStoreScraper()

os.system("adb shell 'su -c ./data/local/tmp/frida-server &' &")
os.system("sh add_certificate.sh")

def func(line):
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


    os.system(f"adb shell am start -a android.intent.action.VIEW -d 'market://details?id={apk}'")
    time.sleep(2)
    os.system("adb shell input tap 540 920")

    c = 0
    now = time.time()
    while(c<1 and time.time()-now<15):
    	c = int(os.popen(f"adb shell pm list packages | grep {apk} | wc -l").read())

    c = int(os.popen(f"adb shell pm list packages | grep {apk} | wc -l").read())
    if c<1:
    	print(f"ERROR: App '{apk}' doesn't download!")
    else:
    	time.sleep(2)
    	print('Start traversing')

    os.system(f"python3 traversing.py -p {apk} -d {serialnum} -e BFS -c 1 -s 2 -a 5 -G 1 -t 20 -w 0 -fl frida-scripts/sslunpinning.js -fl frida-scripts/functionharvester.js")


    inpt = input("Press a button to continue...")

    os.system(f"python3 parse_burp-logs.py {apk}")

    print("\n\nData Safety Section Results:\n")
    print("############################")
    os.system(f"python3 dss_descripancies.py {apk}")
    print("############################")


with open(lst_name) as f:
    for line in f:
        func(line)

