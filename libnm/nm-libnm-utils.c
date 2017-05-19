/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-libnm-utils.h"

/*****************************************************************************/

char *
nm_utils_fixup_desc_string (const char *desc)
{
	static const char *const IGNORED_PHRASES[] = {
		"Multiprotocol MAC/baseband processor",
		"Wireless LAN Controller",
		"Wireless LAN Adapter",
		"Wireless Adapter",
		"Network Connection",
		"Wireless Cardbus Adapter",
		"Wireless CardBus Adapter",
		"54 Mbps Wireless PC Card",
		"Wireless PC Card",
		"Wireless PC",
		"PC Card with XJACK(r) Antenna",
		"Wireless cardbus",
		"Wireless LAN PC Card",
		"Technology Group Ltd.",
		"Communication S.p.A.",
		"Business Mobile Networks BV",
		"Mobile Broadband Minicard Composite Device",
		"Mobile Communications AB",
		"(PC-Suite Mode)",
	};
	static const char *const IGNORED_WORDS[] = {
		"Semiconductor",
		"Components",
		"Corporation",
		"Communications",
		"Company",
		"Corp.",
		"Corp",
		"Co.",
		"Inc.",
		"Inc",
		"Incorporated",
		"Ltd.",
		"Limited.",
		"Intel?",
		"chipset",
		"adapter",
		"[hex]",
		"NDIS",
		"Module",
	};
	char *desc_full;
	char *p, *q;
	int i;

	if (!desc || !desc[0])
		return NULL;

	/* restore original non-UTF-8-safe text. */
	desc_full = nm_utils_str_utf8safe_unescape_cp (desc);

	/* replace all invalid UTF-8 bytes with space. */
	p = desc_full;
	while (!g_utf8_validate (p, -1, (const char **) &q)) {
		/* the byte is invalid UTF-8. Replace it with space and proceed. */
		*q = ' ';
		p = q + 1;
	}

	/* replace '_', ',', and ASCII controll characters with space. */
	for (p = desc_full; p[0]; p++) {
		if (   NM_IN_SET (*p, '_', ',')
		    || *p < ' ')
			*p = ' ';
	}

	/* Attempt to shorten ID by ignoring certain phrases */
	for (i = 0; i < G_N_ELEMENTS (IGNORED_PHRASES); i++) {
		p = strstr (desc_full, IGNORED_PHRASES[i]);
		if (p) {
			const char *eow = &p[strlen (IGNORED_PHRASES[i])];

			/* require that the phrase is delimited by space, or
			 * at the beginning or end of the description. */
			if (   (p == desc_full || p[-1] == ' ')
			    && NM_IN_SET (eow[0], '\0', ' '))
				memmove (p, eow, strlen (eow) + 1); /* +1 for the \0 */
		}
	}

	/* Attempt to shorten ID by ignoring certain individual words.
	 * - word-split the description at spaces
	 * - coalesce multiple spaces
	 * - skip over IGNORED_WORDS */
	p = desc_full;
	q = desc_full;
	for (;;) {
		char *eow;
		gsize l;

		/* skip leading spaces. */
		while (p[0] == ' ')
			p++;

		if (!p[0])
			break;

		/* split leading word on first space */
		eow = strchr (p, ' ');
		if (eow)
			*eow = '\0';

		if (nm_utils_strv_find_first ((char **) IGNORED_WORDS,
		                              G_N_ELEMENTS (IGNORED_WORDS),
		                              p) >= 0)
			goto next;

		l = strlen (p);
		if (q != p) {
			if (q != desc_full)
				*q++ = ' ';
			memmove (q, p, l);
		}
		q += l;

next:
		if (!eow)
			break;
		p = eow + 1;
	}

	*q++ = '\0';

	if (!desc_full[0]) {
		g_free (desc_full);
		return NULL;
	}

	nm_assert (g_utf8_validate (desc_full, -1, NULL));
	return desc_full;
}
