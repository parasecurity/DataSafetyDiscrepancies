from datetime import datetime

from google_play_scraper.utils.data_processors import unescape_text

from typing import Callable, List, Any, Optional

from google_play_scraper.utils import nested_lookup


class ElementSpec:
    def __init__(
        self,
        ds_num: Optional[int],
        data_map: List[int],
        post_processor: Callable = None,
        fallback_value: Any = None,
    ):
        self.ds_num = ds_num
        self.data_map = data_map
        self.post_processor = post_processor
        self.fallback_value = fallback_value

    def extract_content(self, source: dict) -> Any:
        try:
            if self.ds_num is None:
                result = nested_lookup(source, self.data_map)
            else:
                result = nested_lookup(
                    source["ds:{}".format(self.ds_num)], self.data_map
                )

            if self.post_processor is not None:
                result = self.post_processor(result)
        except:
            if isinstance(self.fallback_value, ElementSpec):
                result = self.fallback_value.extract_content(source)
            else:
                result = self.fallback_value

        return result


class ElementSpecs:

    Detail = {
        "title": ElementSpec(4, [1, 2, 0, 0]),
        "description": ElementSpec(4, [1, 2, 72, 0, 1], unescape_text),
        "descriptionHTML": ElementSpec(4, [1, 2, 72, 0, 1]),
        "summary": ElementSpec(4, [1, 2, 73, 0, 1], unescape_text),
        "installs": ElementSpec(4, [1, 2, 13, 0]),
        "minInstalls": ElementSpec(4, [1, 2, 13, 1]),
        "realInstalls": ElementSpec(4, [1, 2, 13, 2]),
        "score": ElementSpec(4, [1, 2, 51, 0, 1]),
        "ratings": ElementSpec(4, [1, 2, 51, 2, 1]),
        "reviews": ElementSpec(4, [1, 2, 51, 3, 1]),
        "histogram": ElementSpec(
            4,
            [1, 2, 51, 1],
            lambda container: [
                container[1][1],
                container[2][1],
                container[3][1],
                container[4][1],
                container[5][1],
            ],
            [0, 0, 0, 0, 0],
        ),
        "price": ElementSpec(
            4, [1, 2, 57, 0, 0, 0, 0, 1, 0, 0], lambda price: (price / 1000000) or 0
        ),
        "free": ElementSpec(4, [1, 2, 57, 0, 0, 0, 0, 1, 0, 0], lambda s: s == 0),
        "currency": ElementSpec(4, [1, 2, 57, 0, 0, 0, 0, 1, 0, 1]),
        "sale": ElementSpec(3, [0, 2, 0, 0, 0, 14, 0, 0], bool, False),
        "saleTime": ElementSpec(3, [0, 2, 0, 0, 0, 14, 0, 0]),
        "originalPrice": ElementSpec(
            3, [0, 2, 0, 0, 0, 1, 1, 0], lambda price: (price / 1000000) or 0
        ),
        "saleText": ElementSpec(3, [0, 2, 0, 0, 0, 14, 1]),
        "offersIAP": ElementSpec(4, [1, 2, 19, 0], bool, False),
        "inAppProductPrice": ElementSpec(4, [1, 2, 19, 0]),
        # "size": ElementSpec(8, [0]),
        # "androidVersion": ElementSpec(4, [1, 2, 140, 1, 1, 0, 0, 1], lambda s: s.split()[0]),
        # "androidVersionText": ElementSpec(4, [1, 2, 140, 1, 1, 0, 0, 1]),
        "developer": ElementSpec(4, [1, 2, 68, 0]),
        "developerId": ElementSpec(4, [1, 2, 68, 1, 4, 2], lambda s: s.split("id=")[1]),
        "developerEmail": ElementSpec(4, [1, 2, 69, 1, 0]),
        "developerWebsite": ElementSpec(4, [1, 2, 69, 0, 5, 2]),
        "developerAddress": ElementSpec(4, [1, 2, 69, 2, 0]),
        "privacyPolicy": ElementSpec(4, [1, 2, 99, 0, 5, 2]),
        # "developerInternalID": ElementSpec(5, [0, 12, 5, 0, 0]),
        "genre": ElementSpec(4, [1, 2, 79, 0, 0, 0]),
        "genreId": ElementSpec(4, [1, 2, 79, 0, 0, 2]),
        "icon": ElementSpec(4, [1, 2, 95, 0, 3, 2]),
        "headerImage": ElementSpec(4, [1, 2, 96, 0, 3, 2]),
        "screenshots": ElementSpec(
            4, [1, 2, 78, 0], lambda container: [item[3][2] for item in container], []
        ),
        "video": ElementSpec(4, [1, 2, 100, 0, 0, 3, 2]),
        "videoImage": ElementSpec(4, [1, 2, 100, 1, 0, 3, 2]),
        "contentRating": ElementSpec(4, [1, 2, 9, 0]),
        "contentRatingDescription": ElementSpec(4, [1, 2, 9, 2, 1]),
        "adSupported": ElementSpec(4, [1, 2, 48], bool),
        "containsAds": ElementSpec(4, [1, 2, 48], bool, False),
        "released": ElementSpec(4, [1, 2, 10, 0]),
        "updated": ElementSpec(4, [1, 2, 145, 0, 1, 0]),
        "version": ElementSpec(
            4, [1, 2, 140, 0, 0, 0], fallback_value="Varies with device"
        ),
        "recentChanges": ElementSpec(4, [1, 2, 144, 1, 1], unescape_text),
        "recentChangesHTML": ElementSpec(4, [1, 2, 144, 1, 1]),
        "comments": ElementSpec(
            8, [0], lambda container: [item[4] for item in container], []
        ),
        # "editorsChoice": ElementSpec(4, [0, 12, 15, 0], bool, False),
        "dataSafety": ElementSpec(
            5,
            [1, 2, 136, 1],
            lambda container: [
                {
                    "section": ElementSpec(None, [1]).extract_content(container[i]),
                    "summary": ElementSpec(None, [2, 1], None, None).extract_content(
                        container[i]
                    ),
                }
                for i in range(0, len(container))
            ],
        ),
    }

    DetailHelper = {
        "appCollections": ElementSpec(
            6,
            [1, 1],
            lambda collections: [
                {
                    "title": ElementSpec(None, [21, 1, 0]).extract_content(collection),
                    "appIds": [
                        ElementSpec(None, [21, 0, i, 0, 0]).extract_content(collection)
                        for i in range(0, len(collection[21][0]))
                    ],
                }
                for collection in collections
            ],
        ),
        "appCollectionPages": ElementSpec(
            6,
            [1, 1],
            lambda collections: [
                {
                    "title": ElementSpec(None, [21, 1, 0]).extract_content(collection),
                    "url": ElementSpec(None, [21, 1, 2, 4, 2]).extract_content(
                        collection
                    ),
                }
                for collection in collections
            ],
        ),
    }

    Review = {
        "reviewId": ElementSpec(None, [0]),
        "userName": ElementSpec(None, [1, 0]),
        "userImage": ElementSpec(None, [1, 1, 3, 2]),
        "content": ElementSpec(None, [4]),
        "score": ElementSpec(None, [2]),
        "thumbsUpCount": ElementSpec(None, [6]),
        "reviewCreatedVersion": ElementSpec(None, [10]),
        "at": ElementSpec(None, [5, 0], lambda v: datetime.fromtimestamp(v)),
        "replyContent": ElementSpec(None, [7, 1]),
        "repliedAt": ElementSpec(None, [7, 2, 0], lambda v: datetime.fromtimestamp(v)),
    }

    Permission_Type = ElementSpec(None, [0])

    Permission_List = ElementSpec(
        None, [2], lambda container: sorted([item[1] for item in container])
    )

    DataSafety = {
        "dataCollected": ElementSpec(
            3,
            [1, 2, 137, 4, 1, 0],
            lambda collection: {
                ElementSpec(None, [0, 1])
                .extract_content(collection[i]): ElementSpec(
                    None,
                    [4],
                    lambda entrys: [
                        {
                            "name": ElementSpec(None, [0]).extract_content(entrys[j]),
                            "optional": ElementSpec(None, [1]).extract_content(
                                entrys[j]
                            ),
                            "usage": ElementSpec(None, [2], None, None).extract_content(
                                entrys[j]
                            ),
                        }
                        for j in range(0, len(entrys))
                    ],
                )
                .extract_content(collection[i])
                for i in range(0, len(collection))
            },
        ),
        "dataShared": ElementSpec(
            3,
            [1, 2, 137, 4, 0, 0],
            lambda collection: {
                ElementSpec(None, [0, 1])
                .extract_content(collection[i]): ElementSpec(
                    None,
                    [4],
                    lambda entrys: [
                        {
                            "name": ElementSpec(None, [0]).extract_content(entrys[j]),
                            "optional": ElementSpec(None, [1]).extract_content(
                                entrys[j]
                            ),
                            "usage": ElementSpec(None, [2], None, None).extract_content(
                                entrys[j]
                            ),
                        }
                        for j in range(0, len(entrys))
                    ],
                )
                .extract_content(collection[i])
                for i in range(0, len(collection))
            },
        ),
        "securityPractices": ElementSpec(
            3,
            [1, 2, 137, 9, 2],
            lambda container: [
                {
                    "name": ElementSpec(None, [i, 1]).extract_content(container),
                    "description": ElementSpec(None, [i, 2, 1]).extract_content(
                        container
                    ),
                }
                for i in range(0, len(container))
            ],
        ),
    }

    Collection = {
        "apps": ElementSpec(
            3,
            [0, 1, 0, 21, 0],
            lambda collection: [
                ElementSpec(None, [0, 0]).extract_content(entry) for entry in collection
            ],
        )
    }

    Developer = {
        "apps": ElementSpec(
            3,
            [0, 1, 0, 21, 0],
            lambda collection: [
                ElementSpec(None, [0, 0]).extract_content(entry) for entry in collection
            ],
        )
    }
