/* SPDX-License-Identifier: LGPL-2.1+ */

#include "nm-sd-adapt-shared.h"

#include <stdbool.h>

#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "web-util.h"

#if 0 /* NM_IGNORED */
bool http_etag_is_valid(const char *etag) {
        if (isempty(etag))
                return false;

        if (!endswith(etag, "\""))
                return false;

        if (!STARTSWITH_SET(etag, "\"", "W/\""))
                return false;

        return true;
}
#endif /* NM_IGNORED */

bool http_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        p = STARTSWITH_SET(url, "http://", "https://");
        if (!p)
                return false;

        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}

#if 0 /* NM_IGNORED */
bool documentation_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        if (http_url_is_valid(url))
                return true;

        p = STARTSWITH_SET(url, "file:/", "info:", "man:");
        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}
#endif /* NM_IGNORED */
