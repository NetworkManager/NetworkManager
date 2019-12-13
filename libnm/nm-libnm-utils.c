// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-libnm-utils.h"

#include "nm-glib-aux/nm-time-utils.h"
#include "nm-libnm-core-intern/nm-common-macros.h"
#include "nm-object.h"

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
	gint64 ts;

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

	ts = nm_utils_clock_gettime_ns (CLOCK_BOOTTIME);

	g_printerr ("libnm-dbus: %s[%"G_GINT64_FORMAT".%05"G_GINT64_FORMAT"] %s\n",
	            prefix,
	            ts / NM_UTILS_NSEC_PER_SEC,
	            (ts / (NM_UTILS_NSEC_PER_SEC / 10000)) % 10000,
	            msg);
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

/*****************************************************************************/

const NMLDBusMetaIface *const _nml_dbus_meta_ifaces[] = {
	&_nml_dbus_meta_iface_nm,
	&_nml_dbus_meta_iface_nm_accesspoint,
	&_nml_dbus_meta_iface_nm_agentmanager,
	&_nml_dbus_meta_iface_nm_checkpoint,
	&_nml_dbus_meta_iface_nm_connection_active,
	&_nml_dbus_meta_iface_nm_dhcp4config,
	&_nml_dbus_meta_iface_nm_dhcp6config,
	&_nml_dbus_meta_iface_nm_device,
	&_nml_dbus_meta_iface_nm_device_adsl,
	&_nml_dbus_meta_iface_nm_device_bluetooth,
	&_nml_dbus_meta_iface_nm_device_bond,
	&_nml_dbus_meta_iface_nm_device_bridge,
	&_nml_dbus_meta_iface_nm_device_dummy,
	&_nml_dbus_meta_iface_nm_device_generic,
	&_nml_dbus_meta_iface_nm_device_iptunnel,
	&_nml_dbus_meta_iface_nm_device_infiniband,
	&_nml_dbus_meta_iface_nm_device_lowpan,
	&_nml_dbus_meta_iface_nm_device_macsec,
	&_nml_dbus_meta_iface_nm_device_macvlan,
	&_nml_dbus_meta_iface_nm_device_modem,
	&_nml_dbus_meta_iface_nm_device_olpcmesh,
	&_nml_dbus_meta_iface_nm_device_ovsbridge,
	&_nml_dbus_meta_iface_nm_device_ovsinterface,
	&_nml_dbus_meta_iface_nm_device_ovsport,
	&_nml_dbus_meta_iface_nm_device_ppp,
	&_nml_dbus_meta_iface_nm_device_statistics,
	&_nml_dbus_meta_iface_nm_device_team,
	&_nml_dbus_meta_iface_nm_device_tun,
	&_nml_dbus_meta_iface_nm_device_veth,
	&_nml_dbus_meta_iface_nm_device_vlan,
	&_nml_dbus_meta_iface_nm_device_vxlan,
	&_nml_dbus_meta_iface_nm_device_wifip2p,
	&_nml_dbus_meta_iface_nm_device_wireguard,
	&_nml_dbus_meta_iface_nm_device_wired,
	&_nml_dbus_meta_iface_nm_device_wireless,
	&_nml_dbus_meta_iface_nm_device_wpan,
	&_nml_dbus_meta_iface_nm_dnsmanager,
	&_nml_dbus_meta_iface_nm_ip4config,
	&_nml_dbus_meta_iface_nm_ip6config,
	&_nml_dbus_meta_iface_nm_settings,
	&_nml_dbus_meta_iface_nm_settings_connection,
	&_nml_dbus_meta_iface_nm_vpn_connection,
	&_nml_dbus_meta_iface_nm_wifip2ppeer,
};

#define COMMON_PREFIX "org.freedesktop.NetworkManager"

static int
_strcmp_common_prefix (gconstpointer a, gconstpointer b, gpointer user_data)
{
	const NMLDBusMetaIface *iface = a;
	const char *dbus_iface_name = b;

	nm_assert (g_str_has_prefix (iface->dbus_iface_name, COMMON_PREFIX));

	return strcmp (&iface->dbus_iface_name[NM_STRLEN (COMMON_PREFIX)], dbus_iface_name);
}

const NMLDBusMetaIface *
nml_dbus_meta_iface_get (const char *dbus_iface_name)
{
	gssize idx;

	nm_assert (dbus_iface_name);

	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMLDBusMetaIface, dbus_iface_name) == 0);

	/* we assume that NetworkManager only uses unique interface names. E.g. one
	 * interface name always has one particular meaning (and offers one set of
	 * properties, signals and methods). This is a convenient assumption, and
	 * we sure would never violate it when extending NM's D-Bus API. */

	if (NM_STR_HAS_PREFIX (dbus_iface_name, COMMON_PREFIX)) {
		/* optimize, that in fact all our interfaces have the same prefix. */
		idx = nm_utils_ptrarray_find_binary_search ((gconstpointer *) _nml_dbus_meta_ifaces,
		                                            G_N_ELEMENTS (_nml_dbus_meta_ifaces),
		                                            &dbus_iface_name[NM_STRLEN (COMMON_PREFIX)],
		                                            _strcmp_common_prefix,
		                                            NULL,
		                                            NULL,
		                                            NULL);
	} else
		return NULL;

	if (idx < 0)
		return NULL;
	return _nml_dbus_meta_ifaces[idx];
}

const NMLDBusMetaProperty *
nml_dbus_meta_property_get (const NMLDBusMetaIface *meta_iface,
                            const char *dbus_property_name,
                            guint *out_idx)
{
	gssize idx;

	nm_assert (meta_iface);
	nm_assert (dbus_property_name);

	idx = nm_utils_array_find_binary_search (meta_iface->dbus_properties,
	                                         sizeof (meta_iface->dbus_properties[0]),
	                                         meta_iface->n_dbus_properties,
	                                         &dbus_property_name,
	                                         nm_strcmp_p_with_data,
	                                         NULL);
	if (idx < 0) {
		NM_SET_OUT (out_idx, meta_iface->n_dbus_properties);
		return NULL;
	}
	NM_SET_OUT (out_idx, idx);
	return &meta_iface->dbus_properties[idx];
}

void
_nml_dbus_meta_class_init_with_properties_impl (GObjectClass *object_class,
                                                const NMLDBusMetaIface *const*meta_ifaces)
{
	int i_iface;

	nm_assert (G_IS_OBJECT_CLASS (object_class));
	nm_assert (meta_ifaces);
	nm_assert (meta_ifaces[0]);

	for (i_iface = 0; meta_ifaces[i_iface]; i_iface++) {
		const NMLDBusMetaIface *meta_iface = meta_ifaces[i_iface];
		guint8 *reverse_idx;
		guint8 i;

		nm_assert (g_type_is_a (meta_iface->get_type_fcn (), G_OBJECT_CLASS_TYPE (object_class)));
		nm_assert (meta_iface->n_obj_properties > 0);
		nm_assert (meta_iface->obj_properties);
		nm_assert (meta_iface->obj_properties_reverse_idx[0] == 0);
		nm_assert (meta_iface->obj_properties == meta_ifaces[0]->obj_properties);

		if (i_iface == 0)
			g_object_class_install_properties (object_class, meta_iface->n_obj_properties, (GParamSpec **) meta_iface->obj_properties);

		reverse_idx = (guint8 *) meta_iface->obj_properties_reverse_idx;

		for (i = 0; i < meta_iface->n_obj_properties; i++)
			reverse_idx[i] = 0xFFu;
		for (i = 0; i < meta_iface->n_dbus_properties; i++) {
			const NMLDBusMetaProperty *mpr = &meta_iface->dbus_properties[i];

			if (   mpr->obj_properties_idx != 0
			    && !mpr->obj_property_no_reverse_idx) {
				nm_assert (mpr->obj_properties_idx < meta_iface->n_obj_properties);
				nm_assert (reverse_idx[mpr->obj_properties_idx] == 0xFFu);

				reverse_idx[mpr->obj_properties_idx] = i;
			}
		}
	}
}

gboolean
nm_utils_g_param_spec_is_default (const GParamSpec *pspec)
{
	g_return_val_if_fail (pspec, FALSE);

	if (pspec->value_type == G_TYPE_BOOLEAN)
		return ((((GParamSpecBoolean *) pspec)->default_value) == FALSE);
	if (pspec->value_type == G_TYPE_UCHAR)
		return ((((GParamSpecUChar *) pspec)->default_value) == 0u);
	if (pspec->value_type == G_TYPE_INT)
		return ((((GParamSpecInt *) pspec)->default_value) == 0);
	if (pspec->value_type == G_TYPE_UINT)
		return ((((GParamSpecUInt *) pspec)->default_value) == 0u);
	if (pspec->value_type == G_TYPE_INT64)
		return ((((GParamSpecInt64 *) pspec)->default_value) == 0);
	if (pspec->value_type == G_TYPE_UINT64)
		return ((((GParamSpecUInt64 *) pspec)->default_value) == 0u);
	if (g_type_is_a (pspec->value_type, G_TYPE_ENUM))
		return ((((GParamSpecEnum *) pspec)->default_value) == 0);
	if (g_type_is_a (pspec->value_type, G_TYPE_FLAGS))
		return ((((GParamSpecFlags *) pspec)->default_value) == 0u);
	if (pspec->value_type == G_TYPE_STRING)
		return ((((GParamSpecString *) pspec)->default_value) == NULL);
	if (NM_IN_SET (pspec->value_type, G_TYPE_BYTES,
	                                  G_TYPE_PTR_ARRAY,
	                                  G_TYPE_HASH_TABLE,
	                                  G_TYPE_STRV)) {
		/* boxed types have NULL default. */
		g_return_val_if_fail (G_IS_PARAM_SPEC_BOXED (pspec), FALSE);
		g_return_val_if_fail (G_TYPE_IS_BOXED (pspec->value_type), FALSE);
		return TRUE;
	}
	if (g_type_is_a (pspec->value_type, NM_TYPE_OBJECT)) {
		/* object types have NULL default. */
		g_return_val_if_fail (G_IS_PARAM_SPEC_OBJECT (pspec), FALSE);
		g_return_val_if_fail (G_TYPE_IS_OBJECT (pspec->value_type), FALSE);
		return TRUE;
	}

	/* This function is only used for asserting/testing. It thus
	 * strictly asserts and only support argument types that we expect. */
	g_return_val_if_reached (FALSE);
}
