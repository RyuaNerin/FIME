#include "stdafx.h"

#include "checkLatestRelease.h"

#include <string>

#include <json/json.h>

#include "common.h"
#include "resource.h"
#include "http.h"

RELEASE_RESULT checkLatestRelease()
{
    RELEASE_RESULT result = NETWORK_ERROR;

    std::string body;
    if (getHttp(L"api.github.com", L"/repos/RyuaNerin/FIME/releases/latest", body))
    {
        result = PARSING_ERROR;

        Json::Reader jsonReader;
        Json::Value json;

        if (jsonReader.parse(body, json))
        {
            std::string tag_name = json["tag_name"].asString();
            if (tag_name.compare(FIME_VERSION_STR) == 0)
            {
                result = LATEST;
            }
            else
            {
                result = NEW_RELEASE;
            }
        }
    }

    return result;
}
