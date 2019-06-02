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
 * Copyright 2007 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-libnm-utils.h"

/*****************************************************************************/

static char *
_fixup_string (const char *desc,
               const char *const *ignored_phrases,
               const char *const *ignored_words,
               gboolean square_brackets_sensible)
{
	char *desc_full;
	gboolean in_paren = FALSE;
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

	/* replace '_', ',', ASCII control characters and parentheses, with space. */
	for (p = desc_full; p[0]; p++) {
		if (*p == '(')
			in_paren = TRUE;
		if (   NM_IN_SET (*p, '_', ',')
		    || *p < ' '
		    || in_paren)
			*p = ' ';
		if (*p == ')')
			in_paren = FALSE;
	}

	/* Attempt to shorten ID by ignoring certain phrases */
	for (i = 0; ignored_phrases[i]; i++) {
		p = strstr (desc_full, ignored_phrases[i]);
		if (p) {
			const char *eow = &p[strlen (ignored_phrases[i])];

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
	 * - skip over ignored_words */
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

		if (nm_utils_strv_find_first ((char **) ignored_words, -1, p) >= 0)
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

	p = strchr (desc_full, '[');
	if (p == desc_full) {
		/* All we're left with is in square brackets.
		 * Always prefer that to a blank string.*/
		square_brackets_sensible = TRUE;
	}
	if (square_brackets_sensible) {
		/* If there's a [<string>] that survived the substitution, then the string
		 * is a short form that is generally preferable. */
		q = strchr (desc_full, ']');
		if (p && q > p) {
			p++;
			memmove (desc_full, p, q - p);
			desc_full[q - p] = '\0';
		}
	} else {
		/* [<string>] sometimes contains the preferred human-readable name, but
		 * mostly it's utterly useless. Sigh. Drop it. */
		if (p) {
			if (p > desc_full && p[-1] == ' ')
				p--;
			*p = '\0';
		}
	}

	if (!desc_full[0]) {
		g_free (desc_full);
		return NULL;
	}

	return desc_full;
}

char *
nm_utils_fixup_vendor_string (const char *desc)
{
	static const char *const IGNORED_PHRASES[] = {
		"Access Systems",
		"Business Mobile Networks BV",
		"Communications & Multimedia",
		"Company of Japan",
		"Computer Co.",
		"Computer Corp.",
		"Computer Corporation",
		"Computer Inc.",
		"Computer, Inc.",
		"Information and Communication Products",
		"Macao Commercial Offshore",
		"Mobile Phones",
		"(M) Son",
		"Multimedia Internet Technology",
		"Technology Group Ltd.",
		"Wireless Networks",
		"Wireless Solutions",
		NULL,
	};
	static const char *const IGNORED_WORDS[] = {
		"AB",
		"AG",
		"A/S",
		"ASA",
		"B.V.",
		"Chips",
		"Co.",
		"Co",
		"Communications",
		"Components",
		"Computers",
		"Computertechnik",
		"corp.",
		"Corp.",
		"Corp",
		"Corporation",
		"Design",
		"Electronics",
		"Enterprise",
		"Enterprises",
		"Europe",
		"GmbH",
		"Hardware",
		"[hex]",
		"Holdings",
		"Inc.",
		"Inc",
		"INC.",
		"Incorporated",
		"Instruments",
		"International",
		"Intl.",
		"Labs",
		"Limited.",
		"Limited",
		"Ltd.",
		"Ltd",
		"Microelectronics",
		"Microsystems",
		"MSM",
		"Multimedia",
		"Networks",
		"Norway",
		"Optical",
		"PCS",
		"Semiconductor",
		"Systems",
		"Systemtechnik",
		"Techcenter",
		"Technik",
		"Technologies",
		"Technology",
		"TECHNOLOGY",
		"Telephonics",
		"USA",
		"WCDMA",
		NULL,
	};
	char *desc_full;
	char *p;

	desc_full = _fixup_string (desc, IGNORED_PHRASES, IGNORED_WORDS, TRUE);
	if (!desc_full)
		return NULL;

	/* Chop off everything after a slash. */
	for (p = desc_full; *p; p++) {
		if ((p[0] == ' ' && p[1] == '/') || p[0] == '/') {
			p[0] = '\0';
			break;
		}
	}

	nm_assert (g_utf8_validate (desc_full, -1, NULL));

	return desc_full;
}

char *
nm_utils_fixup_product_string (const char *desc)
{
	static const char *const IGNORED_PHRASES[] = {
		"100/10 MBit",
		"10/100 Mbps",
		"1.0 GbE",
		"10 GbE",
		"10 Gigabit",
		"10 Mbps",
		"1/10 Gigabit",
		"150 Mbps",
		"2.5 GbE",
		"54 Mbps",
		"Attached Port",
		"+ BT",
		"\"CDC Subset\"",
		"CE Media Processor",
		"Controller Area Network",
		"Converged Network",
		"DEC-Tulip compatible",
		"Dish Adapter",
		"Double 108 Mbps",
		"Dual Band",
		"Dual Port",
		"Embedded UTP",
		"Ethernet Connection",
		"Ethernet Pro 100",
		"Express Module",
		"Fabric Adapter",
		"Fast Ethernet",
		"for 10GBASE-T" ,
		"for 10GbE backplane" ,
		"for 10GbE QSFP+" ,
		"for 10GbE SFP+" ,
		"for 1GbE",
		"for 20GbE backplane" ,
		"for 25GbE backplane" ,
		"for 25GbE SFP28" ,
		"for 40GbE backplane" ,
		"for 40GbE QSFP+" ,
		"G Adapter",
		"Gigabit Desktop Network",
		"Gigabit Ethernet",
		"Gigabit or",
		"Host Interface",
		"Host Virtual Interface",
		"IEEE 802.11a/b/g",
		"IEEE 802.11g",
		"IEEE 802.11G",
		"IEEE 802.11n",
		"MAC + PHY",
		"Mini Card",
		"Mini Wireless",
		"multicore SoC",
		"Multi Function",
		"N Draft 11n Wireless",
		"Network Connection",
		"Network Everywhere",
		"N Wireless",
		"N+ Wireless",
		"OCT To Fast Ethernet Converter",
		"PC Card",
		"PCI Express",
		"Platform Controller Hub",
		"Plus Bluetooth",
		"Quad Gigabit",
		"rev 1",
		"rev 17",
		"rev 2",
		"rev A",
		"rev B",
		"rev F",
		"TO Ethernet",
		"Turbo Wireless Adapter",
		"Unified Wire",
		"USB 1.1",
		"USB 2.0",
		"Virtual media for",
		"WiFi Link",
		"+ WiMAX",
		"WiMAX/WiFi Link",
		"Wireless G",
		"Wireless G+",
		"Wireless Lan",
		"Wireless Mini adapter",
		"Wireless Mini Adapter",
		"Wireless N",
		"with 1000-BASE-T interface",
		"with CX4 copper interface",
		"with Range Amplifier",
		"with SR-XFP optical interface",
		"w/ Upgradable Antenna",
		NULL,
	};
	static const char *const IGNORED_WORDS[] = {
		"1000BaseSX",
		"1000BASE-T",
		"1000Base-ZX",
		"100/10M",
		"100baseFx",
		"100Base-MII",
		"100Base-T",
		"100BaseT4",
		"100Base-TX",
		"100BaseTX",
		"100GbE",
		"100Mbps",
		"100MBps",
		"10/100",
		"10/100/1000",
		"10/100/1000Base-T",
		"10/100/1000BASE-T",
		"10/100BaseT",
		"10/100baseTX",
		"10/100BaseTX",
		"10/100/BNC",
		"10/100M",
		"10/20-Gigabit",
		"10/25/40/50GbE",
		"10/40G",
		"10base-FL",
		"10BaseT",
		"10BASE-T",
		"10G",
		"10Gb",
		"10Gb/25Gb",
		"10Gb/25Gb/40Gb/50Gb",
		"10Gbase-T",
		"10GBase-T",
		"10GBASE-T",
		"10GbE",
		"10Gbps",
		"10-Giga",
		"10-Gigabit",
		"10mbps",
		"10Mbps",
		"1/10GbE",
		"1/10-Gigabit",
		"11b/g/n",
		"11g",
		"150Mbps",
		"16Gbps/10Gbps",
		"1GbE",
		"1x2:2",
		"20GbE",
		"25Gb",
		"25GbE",
		"2-Port",
		"2x3:3",
		"3G",
		"3G/4G",
		"3x3:3",
		"40GbE",
		"4G",
		"54g",
		"54M",
		"54Mbps",
		"56k",
		"5G",
		"802.11",
		"802.11a/b/g",
		"802.11abg",
		"802.11a/b/g/n",
		"802.11abgn",
		"802.11ac",
		"802.11ad",
		"802.11a/g",
		"802.11b",
		"802.11b/g",
		"802.11bg",
		"802.11b/g/n",
		"802.11bgn",
		"802.11b/g/n-draft",
		"802.11g",
		"802.11n",
		"802.11N",
		"802.11n/b/g",
		"802.11ng",
		"802AIN",
		"802UIG-1",
		"adapter",
		"Adapter",
		"adaptor",
		"ADSL",
		"Basic",
		"CAN-Bus",
		"card",
		"Card",
		"Cardbus",
		"CardBus",
		"CDMA",
		"CNA",
		"Composite",
		"controller",
		"Controller",
		"Copper",
		"DB",
		"Desktop",
		"device",
		"Device",
		"dongle",
		"driver",
		"Dual-band",
		"Dual-Protocol",
		"EISA",
		"Enhanced",
		"ethernet.",
		"ethernet",
		"Ethernet",
		"Ethernet/RNDIS",
		"ExpressModule",
		"family",
		"Family",
		"Fast/Gigabit",
		"Fiber",
		"gigabit",
		"Gigabit",
		"G-NIC",
		"Hi-Gain",
		"Hi-Speed",
		"HSDPA",
		"HSUPA",
		"integrated",
		"Integrated",
		"interface",
		"LAN",
		"LAN+Winmodem",
		"Laptop",
		"LTE",
		"LTE/UMTS/GSM",
		"MAC",
		"Micro",
		"Mini-Card",
		"Mini-USB",
		"misprogrammed",
		"modem",
		"Modem",
		"Modem/Networkcard",
		"Module",
		"Multimode",
		"Multithreaded",
		"Name:",
		"net",
		"network",
		"Network",
		"n/g/b",
		"NIC",
		"Notebook",
		"OEM",
		"PCI",
		"PCI64",
		"PCIe",
		"PCI-E",
		"PCI-Express",
		"PCI-X",
		"PCMCIA",
		"PDA",
		"PnP",
		"RDMA",
		"RJ-45",
		"Series",
		"Server",
		"SoC",
		"Switch",
		"Technologies",
		"TOE",
		"USB",
		"USB2.0",
		"USB/Ethernet",
		"UTP",
		"UTP/Coax",
		"v1",
		"v1.1",
		"v2",
		"V2.0",
		"v3",
		"v4",
		"wifi",
		"Wi-Fi",
		"WiFi",
		"wireless",
		"Wireless",
		"Wireless-150N",
		"Wireless-300N",
		"Wireless-G",
		"Wireless-N",
		"WLAN",
		NULL,
	};
	char *desc_full;
	char *p;

	desc_full = _fixup_string (desc, IGNORED_PHRASES, IGNORED_WORDS, FALSE);
	if (!desc_full)
		return NULL;

	/* Chop off everything after a '-'. */
	for (p = desc_full; *p; p++) {
		if (p[0] == ' ' && p[1] == '-' && p[2] == ' ') {
			p[0] = '\0';
			break;
		}
	}

	nm_assert (g_utf8_validate (desc_full, -1, NULL));

	return desc_full;
}
