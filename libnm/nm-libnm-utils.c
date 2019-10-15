// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-libnm-utils.h"

/*****************************************************************************/

volatile int _nml_dbus_log_level = 0;

int
_nml_dbus_log_level_init (void)
{
	const GDebugKey keys[] = {
		{ "trace",   _NML_DBUS_LOG_LEVEL_TRACE },
		{ "debug",   _NML_DBUS_LOG_LEVEL_DEBUG },
		{ "warning", _NML_DBUS_LOG_LEVEL_WARN },
		{ "error",   _NML_DBUS_LOG_LEVEL_ERROR },
	};
	int l;

	l =   _NML_DBUS_LOG_LEVEL_INITIALIZED
	    | nm_utils_parse_debug_string (g_getenv ("LIBNM_CLIENT_DEBUG"),
	                                   keys,
	                                   G_N_ELEMENTS (keys));

	if (!g_atomic_int_compare_and_exchange (&_nml_dbus_log_level, 0, l))
		l = g_atomic_int_get (&_nml_dbus_log_level);

	nm_assert (l & _NML_DBUS_LOG_LEVEL_INITIALIZED);
	return l;
}

void
_nml_dbus_log (NMLDBusLogLevel level,
               const char *fmt,
               ...) {
	NMLDBusLogLevel configured_log_level;
	gs_free char *msg = NULL;
	va_list args;
	const char *prefix = "";

	/* we only call _nml_dbus_log() after nml_dbus_log_enabled(), which already does
	 * an atomic access to the variable. Since the value is only initialized once and
	 * never changes, we can just access it without additional locking. */
	configured_log_level = _nml_dbus_log_level;

	nm_assert (level & configured_log_level);

	va_start (args, fmt);
	msg = g_strdup_vprintf (fmt, args);
	va_end (args);

	switch (level) {
	case NML_DBUS_LOG_LEVEL_TRACE:
		prefix = "<trace> ";
		break;
	case NML_DBUS_LOG_LEVEL_DEBUG:
		prefix = "<debug> ";
		break;
	case NML_DBUS_LOG_LEVEL_WARN:
		prefix = "<warn > ";
		if (NM_FLAGS_HAS (configured_log_level, _NML_DBUS_LOG_LEVEL_WARN)) {
			g_warning ("libnm-dbus: %s%s", prefix, msg);
			return;
		}
		break;
	case NML_DBUS_LOG_LEVEL_ERROR:
		prefix = "<error> ";
		if (NM_FLAGS_HAS (configured_log_level, _NML_DBUS_LOG_LEVEL_ERROR)) {
			g_critical ("libnm-dbus: %s%s", prefix, msg);
			return;
		}
		if (NM_FLAGS_HAS (configured_log_level, _NML_DBUS_LOG_LEVEL_WARN)) {
			g_warning ("libnm-dbus: %s%s", prefix, msg);
			return;
		}
		break;
	default:
		break;
	}

	g_printerr ("libnm-dbus: %s%s\n", prefix, msg);
}

/*****************************************************************************/

/* Stolen from dbus-glib */
char *
nm_utils_wincaps_to_dash (const char *caps)
{
	const char *p;
	GString *str;

	str = g_string_new (NULL);
	p = caps;
	while (*p) {
		if (g_ascii_isupper (*p)) {
			if (str->len > 0 && (str->len < 2 || str->str[str->len-2] != '-'))
				g_string_append_c (str, '-');
			g_string_append_c (str, g_ascii_tolower (*p));
		} else
			g_string_append_c (str, *p);
		++p;
	}

	return g_string_free (str, FALSE);
}

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
