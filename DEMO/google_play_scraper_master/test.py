from google_play_scraper.scraper import PlayStoreScraper
from media.serafeim.Data.serafeim.new_jon.google_play_scraper_master import dss

scraper = PlayStoreScraper()
info = scraper.get_app_details("air.cbn.superbook.bible.app.android", country="nl", lang="en_us")
perm = scraper.get_permissions_for_app("air.cbn.superbook.bible.app.android", lang="en_us")
# dss  = scraper.get_app_details("air.cbn.superbook.bible.app.android", country="nl", lang="en_us")

# similar = scraper.get_similar_app_ids_for_app(results[0])

# app_details = scraper.get_multiple_app_details(similar)
print(info, "\n\n", perm)#, "\n\n", dss)