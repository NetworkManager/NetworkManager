/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-sd-adapt-shared.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-file.h"
#include "hostname-util.h"
#include "log.h"
#include "os-util.h"
#include "string-util.h"
#include "strv.h"

#if 0 /* NM_IGNORED */
char* get_default_hostname_raw(void) {
        int r;

        /* Returns the default hostname, and leaves any ??? in place. */

        const char *e = secure_getenv("SYSTEMD_DEFAULT_HOSTNAME");
        if (e) {
                if (hostname_is_valid(e, VALID_HOSTNAME_QUESTION_MARK))
                        return strdup(e);

                log_debug("Invalid hostname in $SYSTEMD_DEFAULT_HOSTNAME, ignoring: %s", e);
        }

        _cleanup_free_ char *f = NULL;
        r = parse_os_release(NULL, "DEFAULT_HOSTNAME", &f);
        if (r < 0)
                log_debug_errno(r, "Failed to parse os-release, ignoring: %m");
        else if (f) {
                if (hostname_is_valid(f, VALID_HOSTNAME_QUESTION_MARK))
                        return TAKE_PTR(f);

                log_debug("Invalid hostname in os-release, ignoring: %s", f);
        }

        return strdup(FALLBACK_HOSTNAME);
}
#endif /* NM_IGNORED */

bool valid_ldh_char(char c) {
        /* "LDH" → "Letters, digits, hyphens", as per RFC 5890, Section 2.3.1 */

        return ascii_isalpha(c) ||
                ascii_isdigit(c) ||
                c == '-';
}

bool hostname_is_valid(const char *s, ValidHostnameFlags flags) {
        unsigned n_dots = 0;
        const char *p;
        bool dot, hyphen;

        /* Check if s looks like a valid hostname or FQDN. This does not do full DNS validation, but only
         * checks if the name is composed of allowed characters and the length is not above the maximum
         * allowed by Linux (c.f. dns_name_is_valid()). A trailing dot is allowed if
         * VALID_HOSTNAME_TRAILING_DOT flag is set and at least two components are present in the name. Note
         * that due to the restricted charset and length this call is substantially more conservative than
         * dns_name_is_valid(). Doesn't accept empty hostnames, hostnames with leading dots, and hostnames
         * with multiple dots in a sequence. Doesn't allow hyphens at the beginning or end of label. */

        if (isempty(s))
                return false;

        if (streq(s, ".host")) /* Used by the container logic to denote the "root container" */
                return FLAGS_SET(flags, VALID_HOSTNAME_DOT_HOST);

        for (p = s, dot = hyphen = true; *p; p++)
                if (*p == '.') {
                        if (dot || hyphen)
                                return false;

                        dot = true;
                        hyphen = false;
                        n_dots++;

                } else if (*p == '-') {
                        if (dot)
                                return false;

                        dot = false;
                        hyphen = true;

                } else {
                        if (!valid_ldh_char(*p) && (*p != '?' || !FLAGS_SET(flags, VALID_HOSTNAME_QUESTION_MARK)))
                                return false;

                        dot = false;
                        hyphen = false;
                }

        if (dot && (n_dots < 2 || !FLAGS_SET(flags, VALID_HOSTNAME_TRAILING_DOT)))
                return false;
        if (hyphen)
                return false;

        if (p-s > HOST_NAME_MAX) /* Note that HOST_NAME_MAX is 64 on Linux, but DNS allows domain names up to
                                  * 255 characters */
                return false;

        return true;
}

#if 0 /* NM_IGNORED */
char* hostname_cleanup(char *s) {
        char *p, *d;
        bool dot, hyphen;

        assert(s);

        for (p = s, d = s, dot = hyphen = true; *p && d - s < HOST_NAME_MAX; p++)
                if (*p == '.') {
                        if (dot || hyphen)
                                continue;

                        *(d++) = '.';
                        dot = true;
                        hyphen = false;

                } else if (*p == '-') {
                        if (dot)
                                continue;

                        *(d++) = '-';
                        dot = false;
                        hyphen = true;

                } else if (valid_ldh_char(*p) || *p == '?') {
                        *(d++) = *p;
                        dot = false;
                        hyphen = false;
                }

        if (d > s && IN_SET(d[-1], '-', '.'))
                /* The dot can occur at most once, but we might have multiple
                 * hyphens, hence the loop */
                d--;
        *d = 0;

        return s;
}
#endif /* NM_IGNORED */

bool is_localhost(const char *hostname) {
        assert(hostname);

        /* This tries to identify local host and domain names
         * described in RFC6761 plus the redhatism of localdomain */

        return STRCASE_IN_SET(
                        hostname,
                        "localhost",
                        "localhost.",
                        "localhost.localdomain",
                        "localhost.localdomain.") ||
                endswith_no_case(hostname, ".localhost") ||
                endswith_no_case(hostname, ".localhost.") ||
                endswith_no_case(hostname, ".localhost.localdomain") ||
                endswith_no_case(hostname, ".localhost.localdomain.");
}

#if 0 /* NM_IGNORED */
int get_pretty_hostname(char **ret) {
        _cleanup_free_ char *n = NULL;
        int r;

        assert(ret);

        r = parse_env_file(NULL, "/etc/machine-info", "PRETTY_HOSTNAME", &n);
        if (r < 0)
                return r;

        if (isempty(n))
                return -ENXIO;

        *ret = TAKE_PTR(n);
        return 0;
}
#endif /* NM_IGNORED */
