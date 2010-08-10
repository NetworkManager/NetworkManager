/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2010 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <string.h>

#include "nm-policy-hosts.h"

#define FALLBACK_HOSTNAME4 "localhost.localdomain"
#define FALLBACK_HOSTNAME6 "localhost6.localdomain6"

static void
test_generic (const char *before,
              const char *after,
              const char *hostname,
              const char *ip4_addr,
              const char *ip6_addr,
              gboolean expect_error)
{
	char **lines;
	GString *newc;
	GError *error = NULL;

	/* Get the new /etc/hosts contents */
	lines = g_strsplit_set (before, "\n\r", 0);
	newc = nm_policy_get_etc_hosts ((const char **) lines,
	                                strlen (before),
	                                hostname,
	                                FALLBACK_HOSTNAME4,
	                                FALLBACK_HOSTNAME6,
	                                ip4_addr,
	                                ip6_addr,
	                                &error);
	g_strfreev (lines);

	if (expect_error) {
		g_assert (newc == NULL);
		g_assert (error != NULL);
		g_clear_error (&error);
	} else if (after == NULL) {
		/* No change to /etc/hosts required */
#if 0
		if (newc != NULL) {
			g_message ("\n- NEW ---------------------------------\n"
			           "%s"
			           "- EXPECTED NONE -------------------------\n",
			           newc->str);
		}
#endif
		g_assert (newc == NULL);
		g_assert (error == NULL);
	} else {
		g_assert (newc != NULL);
		g_assert (error == NULL);

#if 0
		g_message ("\n- NEW ---------------------------------\n"
		           "%s"
		           "- EXPECTED ------------------------------\n"
		           "%s"
		           "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n",
		           newc->str, after);
#endif
		g_assert (strlen (newc->str) == strlen (after));
		g_assert (strcmp (newc->str, after) == 0);
		g_string_free (newc, TRUE);
	}
}

/*******************************************/

static const char *generic_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_generic (void)
{
	test_generic (generic_before, NULL, "localhost.localdomain", NULL, NULL, FALSE);
}

/*******************************************/

static const char *generic_no_boilerplate_before = \
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_generic_no_boilerplate (void)
{
	test_generic (generic_no_boilerplate_before, NULL, "localhost.localdomain", NULL, NULL, FALSE);
}

/*******************************************/

static const char *generic_no_boilerplate_no_lh_before = \
	"127.0.0.1	localhost.localdomain\n"
	"::1		localhost6.localdomain6	localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *generic_no_boilerplate_no_lh_after = \
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_generic_no_boilerplate_no_lh (void)
{
	test_generic (generic_no_boilerplate_no_lh_before,
	              generic_no_boilerplate_no_lh_after,
	              "localhost.localdomain",
	              NULL,
	              NULL,
	              FALSE);
}

/*******************************************/


static const char *generic_no_boilerplate_no_lh_no_host_before = \
	"127.0.0.1	localhost.localdomain\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *generic_no_boilerplate_no_lh_no_host_after = \
	"127.0.0.1	comet	localhost.localdomain	localhost\n"
	"::1	comet	localhost6.localdomain6	localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_generic_no_boilerplate_no_lh_no_host (void)
{
	test_generic (generic_no_boilerplate_no_lh_no_host_before,
	              generic_no_boilerplate_no_lh_no_host_after,
	              "comet",
	              NULL,
	              NULL,
	              FALSE);
}

/*******************************************/
static const char *named_generic_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	playboy localhost\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_named_generic (void)
{
	test_generic (named_generic_before, NULL, "playboy", NULL, NULL, FALSE);
}

/*******************************************/

static const char *named4_non127_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	tomcat	localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"192.168.1.2	tomcat\n";

static void
test_hosts_named4_non127 (void)
{
	test_generic (named4_non127_before, NULL, "tomcat", "192.168.1.2", NULL, FALSE);
}

/*******************************************/

static const char *named6_non127_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	tomcat localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"3001:abba::3234 tomcat\n";

static void
test_hosts_named6_non127 (void)
{
	test_generic (named6_non127_before, NULL, "tomcat", NULL, "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *named4_non127_more_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	tomcat	localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"192.168.1.2	tomcat\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"127.0.0.1	srx.main.ebayrtm.com\n"
	"127.0.0.1	cdn5.tribalfusion.com\n";

static void
test_hosts_named4_non127_more (void)
{
	test_generic (named4_non127_more_before, NULL, "tomcat", "192.168.1.2", NULL, FALSE);
}

/*******************************************/

static const char *named6_non127_more_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	tomcat localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"3001:abba::3234	tomcat\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"127.0.0.1	srx.main.ebayrtm.com\n"
	"127.0.0.1	cdn5.tribalfusion.com\n";

static void
test_hosts_named6_non127_more (void)
{
	test_generic (named6_non127_more_before, NULL, "tomcat", NULL, "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *named_no_lh_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"192.168.1.2	tomcat\n";

static const char *named_no_lh_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	tomcat	localhost6.localdomain6	localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"192.168.1.2	tomcat\n";

static void
test_hosts_named_no_localhost (void)
{
	test_generic (named_no_lh_before, named_no_lh_after, "tomcat", "192.168.1.2", NULL, FALSE);
}

/*******************************************/

static const char *no_lh_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	tomcat\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *no_lh_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	tomcat	localhost.localdomain	localhost\n"
	"::1	tomcat	localhost6.localdomain6	localhost6\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_no_localhost (void)
{
	test_generic (no_lh_before, no_lh_after, "tomcat", NULL, NULL, FALSE);
}

/*******************************************/

static const char *named_last_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4 sparcbook.ausil.us\n"
	"::1         localhost localhost.localdomain localhost6 localhost6.localdomain6 sparcbook.ausil.us\n";

static void
test_hosts_named_last (void)
{
	test_generic (named_last_before, NULL, "sparcbook.ausil.us", NULL, NULL, FALSE);
}

/*******************************************/

static const char *no_host4_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"127.0.0.1	srx.main.ebayrtm.com\n"
	"127.0.0.1	cdn5.tribalfusion.com\n"
	"127.0.0.1	a.tribalfusion.com\n";

static const char *no_host4_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	comet	localhost.localdomain	localhost\n"
	"::1	comet	localhost6.localdomain6	localhost6\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"127.0.0.1	srx.main.ebayrtm.com\n"
	"127.0.0.1	cdn5.tribalfusion.com\n"
	"127.0.0.1	a.tribalfusion.com\n";

static void
test_hosts_no_host4 (void)
{
	test_generic (no_host4_before, no_host4_after, "comet", NULL, NULL, FALSE);
}

/*******************************************/

static const char *no_host6_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *no_host6_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	comet	localhost.localdomain	localhost\n"
	"::1	comet	localhost6.localdomain6	localhost6\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_no_host6 (void)
{
	test_generic (no_host6_before, no_host6_after, "comet", NULL, NULL, FALSE);
}

/*******************************************/

static const char *named46_non127_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.2 comet\n"
	"3001:abba::3234 comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_named46_non127 (void)
{
	test_generic (named46_non127_before, NULL, "comet", "192.168.1.2", "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *named46_non127_long_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.2 comet.space	comet\n"
	"3001:abba::3234 comet.space	comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_named46_non127_long (void)
{
	test_generic (named46_non127_long_before, NULL, "comet.space", "192.168.1.2", "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *named46_non127_other4_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.3	comet\n"
	"3001:abba::3234	comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *named46_non127_other4_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"192.168.1.2	comet	# Added by NetworkManager\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.3	comet\n"
	"3001:abba::3234	comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_named46_non127_other4 (void)
{
	test_generic (named46_non127_other4_before, named46_non127_other4_after, "comet", "192.168.1.2", "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *named46_non127_other4_long_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.3	comet.space\n"
	"3001:abba::3234	comet.space\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *named46_non127_other4_long_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"192.168.1.2	comet.space	comet	# Added by NetworkManager\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.3	comet.space\n"
	"3001:abba::3234	comet.space\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_named46_non127_other4_long (void)
{
	test_generic (named46_non127_other4_long_before, named46_non127_other4_long_after, "comet.space", "192.168.1.2", "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *named46_non127_other6_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.2	comet\n"
	"3001:abba::9675	comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *named46_non127_other6_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"3001:abba::3234	comet	# Added by NetworkManager\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.2	comet\n"
	"3001:abba::9675	comet\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_named46_non127_other6 (void)
{
	test_generic (named46_non127_other6_before, named46_non127_other6_after, "comet", "192.168.1.2", "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *named46_non127_other6_long_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.2	comet.space\n"
	"3001:abba::9675	comet.space\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *named46_non127_other6_long_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"3001:abba::3234	comet.space	comet	# Added by NetworkManager\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.2	comet.space\n"
	"3001:abba::9675	comet.space\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_named46_non127_other6_long (void)
{
	test_generic (named46_non127_other6_long_before, named46_non127_other6_long_after, "comet.space", "192.168.1.2", "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *unnamed46_non127_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *unnamed46_non127_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"192.168.1.2	comet	# Added by NetworkManager\n"
	"3001:abba::3234	comet	# Added by NetworkManager\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_unnamed46_non127 (void)
{
	test_generic (unnamed46_non127_before, unnamed46_non127_after, "comet", "192.168.1.2", "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *unnamed46_non127_long_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *unnamed46_non127_long_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"192.168.1.2	comet.space	comet	# Added by NetworkManager\n"
	"3001:abba::3234	comet.space	comet	# Added by NetworkManager\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_unnamed46_non127_long (void)
{
	test_generic (unnamed46_non127_long_before, unnamed46_non127_long_after, "comet.space", "192.168.1.2", "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *named46_non127_wrong_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"192.168.1.3	comet	# Added by NetworkManager\n"
	"3001:abba::9876	comet	# Added by NetworkManager\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static const char *named46_non127_wrong_after = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"192.168.1.2	comet	# Added by NetworkManager\n"
	"3001:abba::3234	comet	# Added by NetworkManager\n"
	"127.0.0.1	localhost.localdomain	localhost\n"
	"::1	localhost6.localdomain6	localhost6\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n";

static void
test_hosts_named46_non127_wrong (void)
{
	test_generic (named46_non127_wrong_before, named46_non127_wrong_after, "comet", "192.168.1.2", "3001:abba::3234", FALSE);
}

/*******************************************/

static const char *long_before = \
	"# Do not remove the following line, or various programs\n"
	"# that require network functionality will fail.\n"
	"127.0.0.1	localhost.localdomain	localhost	comet\n"
	"::1		localhost6.localdomain6 localhost6\n"
	"\n"
	"127.0.0.1	lcmd.us.intellitxt.com\n"
	"127.0.0.1	adserver.adtech.de\n"
	"127.0.0.1	a.as-us.falkag.net\n"
	"127.0.0.1	a.as-eu.falkag.net\n"
	"127.0.0.1	ads.doubleclick.com\n"
	"\n"
	"# random comment\n"
	"127.0.0.1	m1.2mdn.net\n"
	"127.0.0.1	ds.serving-sys.com\n"
	"127.0.0.1	pagead2.googlesyndication.com\n"
	"127.0.0.1	ad.doubleclick.com\n"
	"127.0.0.1	ad.doubleclick.net\n"
	"127.0.0.1	oascentral.movietickets.com\n"
	"127.0.0.1	view.atdmt.com\n"
	"127.0.0.1	ads.chumcity.com\n"
	"127.0.0.1	ads.as4x.tmcs.net\n"
	"127.0.0.1	n4403ad.doubleclick.net\n"
	"127.0.0.1	www.assoc-amazon.com\n"
	"127.0.0.1	s25.sitemeter.com\n"
	"127.0.0.1	adlog.com.com\n"
	"127.0.0.1	ahs.laptopmag.com\n"
	"127.0.0.1	altfarm.mediaplex.com\n"
	"127.0.0.1	ads.addynamix.com\n"
	"127.0.0.1	srx.main.ebayrtm.com\n"
	"127.0.0.1	cdn5.tribalfusion.com\n"
	"127.0.0.1	a.tribalfusion.com\n";


static void
test_hosts_long (void)
{
	test_generic (long_before, NULL, "comet", NULL, NULL, FALSE);
}

/*******************************************/

typedef struct {
	const char *line;
	const char *token;
	gboolean expected;
} Foo;

static Foo foo[] = {
	/* Using \t here to easily differentiate tabs vs. spaces for testing */
	{ "127.0.0.1\tfoobar\tblah", "blah", TRUE },
	{ "", "blah", FALSE },
	{ "1.1.1.1\tbork\tfoo", "blah", FALSE },
	{ "127.0.0.1 foobar\tblah", "blah", TRUE },
	{ "127.0.0.1 foobar blah", "blah", TRUE },
	{ "127.0.0.1 localhost", "localhost.localdomain", FALSE },
	{ "192.168.1.1 blah borkbork", "blah", TRUE },
	{ "192.168.1.1 foobar\tblah borkbork", "blah", TRUE },
	{ "192.168.1.1\tfoobar\tblah\tborkbork", "blah", TRUE },
	{ "192.168.1.1 \tfoobar \tblah \tborkbork\t ", "blah", TRUE },
	{ "\t\t\t\t   \t\t\tasdfadf  a\t\t\t\t\t   \t\t\t\t\t ", "blah", FALSE },
	{ NULL, NULL, FALSE }
};

static void
test_find_token (void)
{
	Foo *iter = &foo[0];

	while (iter->line) {
		gboolean found;

		found = nm_policy_hosts_find_token (iter->line, iter->token);
		if (found != iter->expected) {
			g_warning ("find-token: unexpected token result %d for '%s' <= '%s' (expected %d)",
			           found, iter->line, iter->token, iter->expected);
		}
		g_assert (found == iter->expected);
		iter++;
	}
}

#if GLIB_CHECK_VERSION(2,25,12)
typedef GTestFixtureFunc TCFunc;
#else
typedef void (*TCFunc)(void);
#endif

#define TESTCASE(t, d) g_test_create_case (#t, 0, d, NULL, (TCFunc) t, NULL)

int main (int argc, char **argv)
{
	GTestSuite *suite;

	g_test_init (&argc, &argv, NULL);

	suite = g_test_get_root ();

	g_test_suite_add (suite, TESTCASE (test_find_token, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_generic, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_generic_no_boilerplate, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_generic_no_boilerplate_no_lh, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_generic_no_boilerplate_no_lh_no_host, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named_generic, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named4_non127, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named6_non127, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named4_non127_more, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named6_non127_more, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named46_non127, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named46_non127_long, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named46_non127_other4, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named46_non127_other4_long, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named46_non127_other6, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named46_non127_other6_long, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named46_non127_wrong, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_unnamed46_non127, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_unnamed46_non127_long, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named_no_localhost, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_no_localhost, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_named_last, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_no_host4, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_no_host6, NULL));
	g_test_suite_add (suite, TESTCASE (test_hosts_long, NULL));

	return g_test_run ();
}

