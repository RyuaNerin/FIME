#pragma once

#include "resource.h"

#define FIME_BUFFERSIZE     2048

#define FIME_PROJECT_NAME   L"FIME v" TEXT(FIME_VERSION_STR)

#define FIME_DEFAULT_PATCH_JSON \
"{" \
"  \"version\": \"v3.4 (2017.05.23.0000.0000(2603565, ex1:2017.05.18.0000.0000)\"," \
"  \"x64\": [" \
"    {" \
"      \"patch\":     \"EB\"," \
"      \"signature\": \"741B488B86307100000FBED1488D8E30710000FF5058C686\"" \
"    }," \
"    {" \
"      \"patch\":     \"EB\"," \
"      \"signature\": \"7424488B4E08488B01FF50388B96800400004C8B00488BC8\"" \
"    }" \
"  ]," \
"  \"x32\": [" \
"    {" \
"      \"patch\": \"EB\"," \
"      \"signature\": \"741C8B93184200008B522C0FBEC0508D8B18420000FFD2C6\"" \
"    }," \
"    {" \
"      \"patch\": \"EB\"," \
"      \"signature\": \"74208B4E048B118B421CFFD08B8E9C0300008B108B520451\"" \
"    }" \
"  ]" \
"}"
