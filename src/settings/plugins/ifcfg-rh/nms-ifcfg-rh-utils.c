// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-ifcfg-rh-utils.h"

#include <stdlib.h>

#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#include "nms-ifcfg-rh-common.h"

/*****************************************************************************/

gboolean
nms_ifcfg_rh_utils_parse_unhandled_spec (const char *unhandled_spec,
                                         const char **out_unmanaged_spec,
                                         const char **out_unrecognized_spec)
{
	if (unhandled_spec) {
		if (NM_STR_HAS_PREFIX (unhandled_spec, "unmanaged:")) {
			NM_SET_OUT (out_unmanaged_spec, &unhandled_spec[NM_STRLEN ("unmanaged:")]);
			NM_SET_OUT (out_unrecognized_spec, NULL);
			return TRUE;
		}
		if (NM_STR_HAS_PREFIX (unhandled_spec, "unrecognized:")) {
			NM_SET_OUT (out_unmanaged_spec, NULL);
			NM_SET_OUT (out_unrecognized_spec, &unhandled_spec[NM_STRLEN ("unrecognized:")]);
			return TRUE;
		}
	}
	NM_SET_OUT (out_unmanaged_spec, NULL);
	NM_SET_OUT (out_unrecognized_spec, NULL);
	return FALSE;
}

/*****************************************************************************/

/*
 * Check ';[a-fA-F0-9]{8}' file suffix used for temporary files by rpm when
 * installing packages.
 *
 * Implementation taken from upstart.
 */
static gboolean
check_rpm_temp_suffix (const char *path)
{
	const char *ptr;

	g_return_val_if_fail (path != NULL, FALSE);

	/* Matches *;[a-fA-F0-9]{8}; used by rpm */
	ptr = strrchr (path, ';');
	if (   ptr
	    && strspn (ptr + 1, "abcdefABCDEF0123456789") == 8
	    && !ptr[9])
		return TRUE;
	return FALSE;
}

static gboolean
check_suffix (const char *base, const char *tag)
{
	int len, tag_len;

	g_return_val_if_fail (base != NULL, TRUE);
	g_return_val_if_fail (tag != NULL, TRUE);

	len = strlen (base);
	tag_len = strlen (tag);
	if ((len > tag_len) && !g_ascii_strcasecmp (base + len - tag_len, tag))
		return TRUE;
	return FALSE;
}

gboolean
utils_should_ignore_file (const char *filename, gboolean only_ifcfg)
{
	gs_free char *base = NULL;

	g_return_val_if_fail (filename != NULL, TRUE);

	base = g_path_get_basename (filename);

	/* Only handle ifcfg, keys, and routes files */
	if (strncmp (base, IFCFG_TAG, strlen (IFCFG_TAG)) != 0) {
		if (only_ifcfg)
			return TRUE;
		else if (   strncmp (base, KEYS_TAG, strlen (KEYS_TAG)) != 0
		         && strncmp (base, ROUTE_TAG, strlen (ROUTE_TAG)) != 0
		         && strncmp (base, ROUTE6_TAG, strlen (ROUTE6_TAG)) != 0)
			return TRUE;
	}

	/* But not those that have certain suffixes */
	if (   check_suffix (base, BAK_TAG)
	    || check_suffix (base, TILDE_TAG)
	    || check_suffix (base, ORIG_TAG)
	    || check_suffix (base, REJ_TAG)
	    || check_suffix (base, RPMNEW_TAG)
	    || check_suffix (base, AUGNEW_TAG)
	    || check_suffix (base, AUGTMP_TAG)
	    || check_rpm_temp_suffix (base))
		return TRUE;

	return FALSE;
}

char *
utils_cert_path (const char *parent, const char *suffix, const char *extension)
{
	gs_free char *dir = NULL;
	const char *name;

	g_return_val_if_fail (parent, NULL);
	g_return_val_if_fail (suffix, NULL);
	g_return_val_if_fail (extension, NULL);

	name = utils_get_ifcfg_name (parent, FALSE);
	g_return_val_if_fail (name, NULL);

	dir = g_path_get_dirname (parent);
	return g_strdup_printf ("%s/%s-%s.%s", dir, name, suffix, extension);
}

const char *
utils_get_ifcfg_name (const char *file, gboolean only_ifcfg)
{
	const char *name;

	g_return_val_if_fail (file != NULL, NULL);

	name = strrchr (file, '/');
	if (!name)
		name = file;
	else
		name++;
	if (!*name)
		return NULL;

#define MATCH_TAG_AND_RETURN(name, TAG) \
	G_STMT_START { \
		if (strncmp (name, TAG, NM_STRLEN (TAG)) == 0) { \
			name += NM_STRLEN (TAG); \
			if (name[0] == '\0') \
				return NULL; \
			else \
				return name; \
		} \
	} G_STMT_END

	/* Do not detect alias files and return 'eth0:0' instead of 'eth0'.
	 * Unfortunately, we cannot be sure that our files don't contain colons,
	 * so we cannot reject files with colons.
	 *
	 * Instead, you must not call utils_get_ifcfg_name() with an alias file
	 * or files that are ignored. */
	MATCH_TAG_AND_RETURN (name, IFCFG_TAG);
	if (!only_ifcfg) {
		MATCH_TAG_AND_RETURN (name, KEYS_TAG);
		MATCH_TAG_AND_RETURN (name, ROUTE_TAG);
		MATCH_TAG_AND_RETURN (name, ROUTE6_TAG);
	}

	return NULL;
}

/* Used to get any ifcfg/extra file path from any other ifcfg/extra path
 * in the form <tag><name>.
 */
static char *
utils_get_extra_path (const char *parent, const char *tag)
{
	char *item_path = NULL, *dirname;
	const char *name;

	g_return_val_if_fail (parent != NULL, NULL);
	g_return_val_if_fail (tag != NULL, NULL);

	dirname = g_path_get_dirname (parent);
	if (!dirname)
		g_return_val_if_reached (NULL);

	name = utils_get_ifcfg_name (parent, FALSE);
	if (name) {
		if (!strcmp (dirname, "."))
			item_path = g_strdup_printf ("%s%s", tag, name);
		else
			item_path = g_strdup_printf ("%s/%s%s", dirname, tag, name);
	}
	g_free (dirname);

	return item_path;
}

char *
utils_get_ifcfg_path (const char *parent)
{
	return utils_get_extra_path (parent, IFCFG_TAG);
}

char *
utils_get_keys_path (const char *parent)
{
	return utils_get_extra_path (parent, KEYS_TAG);
}

char *
utils_get_route_path (const char *parent)
{
	return utils_get_extra_path (parent, ROUTE_TAG);
}

char *
utils_get_route6_path (const char *parent)
{
	return utils_get_extra_path (parent, ROUTE6_TAG);
}

shvarFile *
utils_get_extra_ifcfg (const char *parent, const char *tag, gboolean should_create)
{
	shvarFile *ifcfg = NULL;
	char *path;

	path = utils_get_extra_path (parent, tag);
	if (!path)
		return NULL;

	if (should_create && !g_file_test (path, G_FILE_TEST_EXISTS))
		ifcfg = svCreateFile (path);

	if (!ifcfg)
		ifcfg = svOpenFile (path, NULL);

	g_free (path);
	return ifcfg;
}

shvarFile *
utils_get_keys_ifcfg (const char *parent, gboolean should_create)
{
	return utils_get_extra_ifcfg (parent, KEYS_TAG, should_create);
}

shvarFile *
utils_get_route_ifcfg (const char *parent, gboolean should_create)
{
	return utils_get_extra_ifcfg (parent, ROUTE_TAG, should_create);
}

/* Finds out if route file has new or older format
 * Returns TRUE  - new syntax (ADDRESS<n>=a.b.c.d ...), error opening file or empty
 *         FALSE - older syntax, i.e. argument to 'ip route add' (1.2.3.0/24 via 11.22.33.44)
 */
gboolean
utils_has_route_file_new_syntax (const char *filename)
{
	gs_free char *contents_data = NULL;
	gsize len;

	g_return_val_if_fail (filename != NULL, TRUE);

	if (!g_file_get_contents (filename, &contents_data, &len, NULL))
		return TRUE;

	return utils_has_route_file_new_syntax_content (contents_data, len);
}

gboolean
utils_has_route_file_new_syntax_content (const char *contents,
                                         gsize len)
{
	if (len <= 0)
		return TRUE;

	while (TRUE) {
		const char *line = contents;
		char *eol;
		gboolean found = FALSE;

		/* matches regex "^[[:space:]]*ADDRESS[0-9]+=" */

		eol = (char *) strchr (contents, '\n');
		if (eol) {
			eol[0] = '\0';
			contents = &eol[1];
		}

		line = nm_str_skip_leading_spaces (line);
		if (NM_STR_HAS_PREFIX (line, "ADDRESS")) {
			line += NM_STRLEN ("ADDRESS");
			if (g_ascii_isdigit (line[0])) {
				while (g_ascii_isdigit ((++line)[0])) {
					/* pass */
				}
				if (line[0] == '=')
					found = TRUE;
			}
		}

		if (eol) {
			/* restore the line ending. We don't want to mangle the content from
			 * POV of the caller. */
			eol[0] = '\n';
		}

		if (found)
			return TRUE;
		if (!eol)
			return FALSE;
	}
}

gboolean
utils_has_complex_routes (const char *filename, int addr_family)
{
	g_return_val_if_fail (filename, TRUE);

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET)) {
		gs_free char *rules = utils_get_extra_path (filename, RULE_TAG);

		if (g_file_test (rules, G_FILE_TEST_EXISTS))
			return TRUE;
	}

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET6)) {
		gs_free char *rules = utils_get_extra_path (filename, RULE6_TAG);
		if (g_file_test (rules, G_FILE_TEST_EXISTS))
			return TRUE;
	}

	return FALSE;
}

/* Find out if the 'alias' file name might be an alias file for 'ifcfg' file name,
 * or any alias when 'ifcfg' is NULL. Does not check that it's actually a valid
 * alias name; that happens in reader.c
 */
gboolean
utils_is_ifcfg_alias_file (const char *alias, const char *ifcfg)
{
	g_return_val_if_fail (alias != NULL, FALSE);

	if (strncmp (alias, IFCFG_TAG, strlen (IFCFG_TAG)))
		return FALSE;

	if (ifcfg) {
		size_t len = strlen (ifcfg);

		return (strncmp (alias, ifcfg, len) == 0 && alias[len] == ':');
	} else {
		return (strchr (alias, ':') != NULL);
	}
}

char *
utils_detect_ifcfg_path (const char *path, gboolean only_ifcfg)
{
	const char *base;

	g_return_val_if_fail (path != NULL, NULL);

	if (utils_should_ignore_file (path, only_ifcfg))
		return NULL;

	base = strrchr (path, '/');
	if (!base)
		base = path;
	else
		base += 1;

	if (NM_STR_HAS_PREFIX (base, IFCFG_TAG)) {
		if (base[NM_STRLEN (IFCFG_TAG)] == '\0')
			return NULL;
		if (utils_is_ifcfg_alias_file (base, NULL)) {
			gs_free char *ifcfg = NULL;
			char *ptr;

			ifcfg = g_strdup (path);
			ptr = strrchr (ifcfg, ':');
			if (   ptr
			    && ptr > ifcfg
			    && !strchr (ptr, '/')) {
				*ptr = '\0';
				if (g_file_test (ifcfg, G_FILE_TEST_EXISTS)) {
					/* the file has a colon, so it is probably an alias.
					 * To be ~more~ certain that this is an alias file,
					 * check whether a corresponding base file exists. */
					if (only_ifcfg)
						return NULL;
					return g_steal_pointer (&ifcfg);
				}
			}
		}
		return g_strdup (path);
	}

	if (only_ifcfg)
		return NULL;
	return utils_get_ifcfg_path (path);
}

void
nms_ifcfg_rh_utils_user_key_encode (const char *key, GString *str_buffer)
{
	gsize i;

	nm_assert (key);
	nm_assert (str_buffer);

	for (i = 0; key[i]; i++) {
		char ch = key[i];

		/* we encode the key in only upper case letters, digits, and underscore.
		 * As we expect lower-case letters to be more common, we encode lower-case
		 * letters as upper case, and upper-case letters with a leading underscore. */

		if (ch >= '0' && ch <= '9') {
			g_string_append_c (str_buffer, ch);
			continue;
		}
		if (ch >= 'a' && ch <= 'z') {
			g_string_append_c (str_buffer, ch - 'a' + 'A');
			continue;
		}
		if (ch == '.') {
			g_string_append (str_buffer, "__");
			continue;
		}
		if (ch >= 'A' && ch <= 'Z') {
			g_string_append_c (str_buffer, '_');
			g_string_append_c (str_buffer, ch);
			continue;
		}
		g_string_append_printf (str_buffer, "_%03o", (unsigned) ch);
	}
}

gboolean
nms_ifcfg_rh_utils_user_key_decode (const char *name, GString *str_buffer)
{
	gsize i;

	nm_assert (name);
	nm_assert (str_buffer);

	if (!name[0])
		return FALSE;

	for (i = 0; name[i]; ) {
		char ch = name[i];

		if (ch >= '0' && ch <= '9') {
			g_string_append_c (str_buffer, ch);
			i++;
			continue;
		}
		if (ch >= 'A' && ch <= 'Z') {
			g_string_append_c (str_buffer, ch - 'A' + 'a');
			i++;
			continue;
		}

		if (ch == '_') {
			ch = name[i + 1];
			if (ch == '_') {
				g_string_append_c (str_buffer, '.');
				i += 2;
				continue;
			}
			if (ch >= 'A' && ch <= 'Z') {
				g_string_append_c (str_buffer, ch);
				i += 2;
				continue;
			}
			if (ch >= '0' && ch <= '7') {
				char ch2, ch3;
				unsigned v;

				ch2 = name[i + 2];
				if (!(ch2 >= '0' && ch2 <= '7'))
					return FALSE;

				ch3 = name[i + 3];
				if (!(ch3 >= '0' && ch3 <= '7'))
					return FALSE;

#define OCTAL_VALUE(ch) ((unsigned) ((ch) - '0'))
				v = (OCTAL_VALUE (ch)  << 6) +
				    (OCTAL_VALUE (ch2) << 3) +
				     OCTAL_VALUE (ch3);
				if (   v > 0xFF
				    || v == 0)
					return FALSE;
				ch = (char) v;
				if (   (ch >= 'A' && ch <= 'Z')
				    || (ch >= '0' && ch <= '9')
				    || (ch == '.')
				    || (ch >= 'a' && ch <= 'z')) {
					/* such characters are not expected to be encoded via
					 * octal representation. The encoding is invalid. */
					return FALSE;
				}
				g_string_append_c (str_buffer, ch);
				i += 4;
				continue;
			}
			return FALSE;
		}

		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

const char *const _nm_ethtool_ifcfg_names[] = {
#define ETHT_NAME(eid, ename) \
[eid - _NM_ETHTOOL_ID_FEATURE_FIRST] = ""ename""
	/* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_ESP_HW_OFFLOAD,               "esp-hw-offload"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_ESP_TX_CSUM_HW_OFFLOAD,       "esp-tx-csum-hw-offload"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_FCOE_MTU,                     "fcoe-mtu"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_GRO,                          "gro"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_GSO,                          "gso"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_HIGHDMA,                      "highdma"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_HW_TC_OFFLOAD,                "hw-tc-offload"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_L2_FWD_OFFLOAD,               "l2-fwd-offload"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_LOOPBACK,                     "loopback"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_LRO,                          "lro"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_NTUPLE,                       "ntuple"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RX,                           "rx"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RXHASH,                       "rxhash"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RXVLAN,                       "rxvlan"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RX_ALL,                       "rx-all"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RX_FCS,                       "rx-fcs"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RX_GRO_HW,                    "rx-gro-hw"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RX_UDP_TUNNEL_PORT_OFFLOAD,   "rx-udp_tunnel-port-offload"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RX_VLAN_FILTER,               "rx-vlan-filter"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_FILTER,          "rx-vlan-stag-filter"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_HW_PARSE,        "rx-vlan-stag-hw-parse"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_SG,                           "sg"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TLS_HW_RECORD,                "tls-hw-record"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TLS_HW_TX_OFFLOAD,            "tls-hw-tx-offload"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TSO,                          "tso"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX,                           "tx"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TXVLAN,                       "txvlan"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_FCOE_CRC,         "tx-checksum-fcoe-crc"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV4,             "tx-checksum-ipv4"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV6,             "tx-checksum-ipv6"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IP_GENERIC,       "tx-checksum-ip-generic"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_SCTP,             "tx-checksum-sctp"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_ESP_SEGMENTATION,          "tx-esp-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_FCOE_SEGMENTATION,         "tx-fcoe-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_GRE_CSUM_SEGMENTATION,     "tx-gre-csum-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_GRE_SEGMENTATION,          "tx-gre-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_GSO_PARTIAL,               "tx-gso-partial"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_GSO_ROBUST,                "tx-gso-robust"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_IPXIP4_SEGMENTATION,       "tx-ipxip4-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_IPXIP6_SEGMENTATION,       "tx-ipxip6-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_NOCACHE_COPY,              "tx-nocache-copy"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER,            "tx-scatter-gather"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER_FRAGLIST,   "tx-scatter-gather-fraglist"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_SCTP_SEGMENTATION,         "tx-sctp-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_TCP6_SEGMENTATION,         "tx-tcp6-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_TCP_ECN_SEGMENTATION,      "tx-tcp-ecn-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_TCP_MANGLEID_SEGMENTATION, "tx-tcp-mangleid-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_TCP_SEGMENTATION,          "tx-tcp-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_UDP_SEGMENTATION,          "tx-udp-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_CSUM_SEGMENTATION, "tx-udp_tnl-csum-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_SEGMENTATION,      "tx-udp_tnl-segmentation"),
	ETHT_NAME (NM_ETHTOOL_ID_FEATURE_TX_VLAN_STAG_HW_INSERT,       "tx-vlan-stag-hw-insert"),
};

static
NM_UTILS_STRING_TABLE_LOOKUP_DEFINE (
	_get_ethtoolid_by_name,
	NMEthtoolID,
	{ nm_assert (name); },
	{ return NM_ETHTOOL_ID_UNKNOWN; },

	/* Map the names from kernel/ethtool/ifcfg to NMEthtoolID. Note that ethtool utility has built-in
	 * features and NetworkManager's API follows the naming of these built-in features, whenever
	 * they exist.
	 * For example, NM's "ethtool.feature-ntuple" corresponds to ethtool utility's "ntuple"
	 * feature. However the underlying kernel feature is called "rx-ntuple-filter" (as reported
	 * for ETH_SS_FEATURES).
	 *
	 * With ethtool utility, whose command line we attempt to parse here, the user can also
	 * specify the name of the underlying kernel feature directly. So, check whether that is
	 * the case and if yes, map them to the corresponding NetworkManager's features.
	 *
	 * That is why there are duplicate IDs in this list. */
	{ "esp-hw-offload",               NM_ETHTOOL_ID_FEATURE_ESP_HW_OFFLOAD               },
	{ "esp-tx-csum-hw-offload",       NM_ETHTOOL_ID_FEATURE_ESP_TX_CSUM_HW_OFFLOAD       },
	{ "fcoe-mtu",                     NM_ETHTOOL_ID_FEATURE_FCOE_MTU                     },
	{ "gro",                          NM_ETHTOOL_ID_FEATURE_GRO                          },
	{ "gso",                          NM_ETHTOOL_ID_FEATURE_GSO                          },
	{ "highdma",                      NM_ETHTOOL_ID_FEATURE_HIGHDMA                      },
	{ "hw-tc-offload",                NM_ETHTOOL_ID_FEATURE_HW_TC_OFFLOAD                },
	{ "l2-fwd-offload",               NM_ETHTOOL_ID_FEATURE_L2_FWD_OFFLOAD               },
	{ "loopback",                     NM_ETHTOOL_ID_FEATURE_LOOPBACK                     },
	{ "lro",                          NM_ETHTOOL_ID_FEATURE_LRO                          },
	{ "ntuple",                       NM_ETHTOOL_ID_FEATURE_NTUPLE                       },
	{ "rx",                           NM_ETHTOOL_ID_FEATURE_RX                           },
	{ "rx-all",                       NM_ETHTOOL_ID_FEATURE_RX_ALL                       },
	{ "rx-checksum",                  NM_ETHTOOL_ID_FEATURE_RX                           }, // kernel-only name
	{ "rx-fcs",                       NM_ETHTOOL_ID_FEATURE_RX_FCS                       },
	{ "rx-gro",                       NM_ETHTOOL_ID_FEATURE_GRO                          }, // kernel-only name
	{ "rx-gro-hw",                    NM_ETHTOOL_ID_FEATURE_RX_GRO_HW                    },
	{ "rx-hashing",                   NM_ETHTOOL_ID_FEATURE_RXHASH                       }, // kernel-only name
	{ "rx-lro",                       NM_ETHTOOL_ID_FEATURE_LRO                          }, // kernel-only name
	{ "rx-ntuple-filter",             NM_ETHTOOL_ID_FEATURE_NTUPLE                       }, // kernel-only name
	{ "rx-udp_tunnel-port-offload",   NM_ETHTOOL_ID_FEATURE_RX_UDP_TUNNEL_PORT_OFFLOAD   },
	{ "rx-vlan-filter",               NM_ETHTOOL_ID_FEATURE_RX_VLAN_FILTER               },
	{ "rx-vlan-hw-parse",             NM_ETHTOOL_ID_FEATURE_RXVLAN                       }, // kernel-only name
	{ "rx-vlan-stag-filter",          NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_FILTER          },
	{ "rx-vlan-stag-hw-parse",        NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_HW_PARSE        },
	{ "rxhash",                       NM_ETHTOOL_ID_FEATURE_RXHASH                       },
	{ "rxvlan",                       NM_ETHTOOL_ID_FEATURE_RXVLAN                       },
	{ "sg",                           NM_ETHTOOL_ID_FEATURE_SG                           },
	{ "tls-hw-record",                NM_ETHTOOL_ID_FEATURE_TLS_HW_RECORD                },
	{ "tls-hw-tx-offload",            NM_ETHTOOL_ID_FEATURE_TLS_HW_TX_OFFLOAD            },
	{ "tso",                          NM_ETHTOOL_ID_FEATURE_TSO                          },
	{ "tx",                           NM_ETHTOOL_ID_FEATURE_TX                           },
	{ "tx-checksum-fcoe-crc",         NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_FCOE_CRC         },
	{ "tx-checksum-ip-generic",       NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IP_GENERIC       },
	{ "tx-checksum-ipv4",             NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV4             },
	{ "tx-checksum-ipv6",             NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV6             },
	{ "tx-checksum-sctp",             NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_SCTP             },
	{ "tx-esp-segmentation",          NM_ETHTOOL_ID_FEATURE_TX_ESP_SEGMENTATION          },
	{ "tx-fcoe-segmentation",         NM_ETHTOOL_ID_FEATURE_TX_FCOE_SEGMENTATION         },
	{ "tx-generic-segmentation",      NM_ETHTOOL_ID_FEATURE_GSO                          }, // kernel-only name
	{ "tx-gre-csum-segmentation",     NM_ETHTOOL_ID_FEATURE_TX_GRE_CSUM_SEGMENTATION     },
	{ "tx-gre-segmentation",          NM_ETHTOOL_ID_FEATURE_TX_GRE_SEGMENTATION          },
	{ "tx-gso-partial",               NM_ETHTOOL_ID_FEATURE_TX_GSO_PARTIAL               },
	{ "tx-gso-robust",                NM_ETHTOOL_ID_FEATURE_TX_GSO_ROBUST                },
	{ "tx-ipxip4-segmentation",       NM_ETHTOOL_ID_FEATURE_TX_IPXIP4_SEGMENTATION       },
	{ "tx-ipxip6-segmentation",       NM_ETHTOOL_ID_FEATURE_TX_IPXIP6_SEGMENTATION       },
	{ "tx-nocache-copy",              NM_ETHTOOL_ID_FEATURE_TX_NOCACHE_COPY              },
	{ "tx-scatter-gather",            NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER            },
	{ "tx-scatter-gather-fraglist",   NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER_FRAGLIST   },
	{ "tx-sctp-segmentation",         NM_ETHTOOL_ID_FEATURE_TX_SCTP_SEGMENTATION         },
	{ "tx-tcp-ecn-segmentation",      NM_ETHTOOL_ID_FEATURE_TX_TCP_ECN_SEGMENTATION      },
	{ "tx-tcp-mangleid-segmentation", NM_ETHTOOL_ID_FEATURE_TX_TCP_MANGLEID_SEGMENTATION },
	{ "tx-tcp-segmentation",          NM_ETHTOOL_ID_FEATURE_TX_TCP_SEGMENTATION          },
	{ "tx-tcp6-segmentation",         NM_ETHTOOL_ID_FEATURE_TX_TCP6_SEGMENTATION         },
	{ "tx-udp-segmentation",          NM_ETHTOOL_ID_FEATURE_TX_UDP_SEGMENTATION          },
	{ "tx-udp_tnl-csum-segmentation", NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_CSUM_SEGMENTATION },
	{ "tx-udp_tnl-segmentation",      NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_SEGMENTATION      },
	{ "tx-vlan-hw-insert",            NM_ETHTOOL_ID_FEATURE_TXVLAN                       }, // kernel-only name
	{ "tx-vlan-stag-hw-insert",       NM_ETHTOOL_ID_FEATURE_TX_VLAN_STAG_HW_INSERT       },
	{ "txvlan",                       NM_ETHTOOL_ID_FEATURE_TXVLAN                       },
);

const NMEthtoolData *
nms_ifcfg_rh_utils_get_ethtool_by_name (const char *name)
{
	NMEthtoolID id;

	id = _get_ethtoolid_by_name (name);
	if (id == NM_ETHTOOL_ID_UNKNOWN)
		return NULL;

	nm_assert (_NM_INT_NOT_NEGATIVE (id));
	nm_assert (id < G_N_ELEMENTS (nm_ethtool_data));
	nm_assert (nm_ethtool_data[id]);
	nm_assert (nm_ethtool_data[id]->id == id);
	return nm_ethtool_data[id];
}

/*****************************************************************************/

gboolean
nms_ifcfg_rh_utils_is_numbered_tag_impl (const char *key,
                                         const char *tag,
                                         gsize tag_len,
                                         gint64 *out_idx)
{
	gint64 idx;

	nm_assert (key);
	nm_assert (tag);
	nm_assert (tag_len == strlen (tag));
	nm_assert (tag_len > 0);

	if (strncmp (key, tag, tag_len) != 0)
		return FALSE;

	key += tag_len;

	if (key[0] == '\0') {
		/* The key has no number suffix. We treat this also as a numbered
		 * tag, and it is for certain tags like "IPADDR", but not so much
		 * for others like "ROUTING_RULE_". The caller may want to handle
		 * this case specially. */
		NM_SET_OUT (out_idx, -1);
		return TRUE;
	}

	if (!NM_STRCHAR_ALL (key, ch, g_ascii_isdigit (ch)))
		return FALSE;

	idx = _nm_utils_ascii_str_to_int64 (key, 10, 0, G_MAXINT64, -1);
	if (idx == -1)
		return FALSE;

	NM_SET_OUT (out_idx, idx);
	return TRUE;
}

/*****************************************************************************/

#define _KEY_TYPE(key, flags) { .key_name = ""key"", .key_flags = ((NMS_IFCFG_KEY_TYPE_WELL_KNOWN) | (flags)), }

const NMSIfcfgKeyTypeInfo nms_ifcfg_well_known_keys[] = {
	_KEY_TYPE ("ACD_TIMEOUT",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("ADDRESS",                                     NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("ARPING_WAIT",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("AUTH_RETRIES",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("AUTOCONNECT_PRIORITY",                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("AUTOCONNECT_RETRIES",                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("AUTOCONNECT_SLAVES",                          NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BAND",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BONDING_MASTER",                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BONDING_OPTS",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BOOTPROTO",                                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BRIDGE",                                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BRIDGE_MACADDR",                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BRIDGE_PORT_VLANS",                           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BRIDGE_UUID",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BRIDGE_VLANS",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BRIDGING_OPTS",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BROWSER_ONLY",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("BSSID",                                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("CHANNEL",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("CIPHER_GROUP",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("CIPHER_PAIRWISE",                             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("CONNECTED_MODE",                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("CONNECTION_METERED",                          NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("CTCPROT",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DCB",                                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_FCOE_ADVERTISE,                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_FCOE_ENABLE,                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_FCOE_MODE,                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DCB_APP_FCOE_PRIORITY",                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_FCOE_WILLING,                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_FIP_ADVERTISE,                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_FIP_ENABLE,                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DCB_APP_FIP_PRIORITY",                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_FIP_WILLING,                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_ISCSI_ADVERTISE,                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_ISCSI_ENABLE,                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DCB_APP_ISCSI_PRIORITY",                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_APP_ISCSI_WILLING,                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PFC_ADVERTISE,                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PFC_ENABLE,                            NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PFC_UP,                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PFC_WILLING,                           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PG_ADVERTISE,                          NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PG_ENABLE,                             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PG_ID,                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PG_PCT,                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PG_STRICT,                             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PG_UP2TC,                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PG_UPPCT,                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE (KEY_DCB_PG_WILLING,                            NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DEFAULTKEY",                                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DEFROUTE",                                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DELAY",                                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DEVICE",                                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DEVICETYPE",                                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DEVTIMEOUT",                                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCPV6C",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCPV6_DUID",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCPV6_HOSTNAME",                             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCPV6_HOSTNAME_FLAGS",                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCPV6_IAID",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCPV6_SEND_HOSTNAME",                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCP_CLIENT_ID",                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCP_FQDN",                                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCP_HOSTNAME",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCP_HOSTNAME_FLAGS",                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCP_IAID",                                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCP_SEND_HOSTNAME",                          NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCPv6_DUID",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DHCPv6_IAID",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("DNS",                                         NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("DOMAIN",                                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("ESSID",                                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("ETHTOOL_OPTS",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("ETHTOOL_WAKE_ON_LAN",                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("FILS",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("FILTER",                                      NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("GATEWAY",                                     NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("GATEWAYDEV",                                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("GATEWAY_PING_TIMEOUT",                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("GENERATE_MAC_ADDRESS_MASK",                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("GVRP",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("HWADDR",                                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("HWADDR_BLACKLIST",                            NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_ALTSUBJECT_MATCHES",               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_ANON_IDENTITY",                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_AUTH_TIMEOUT",                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_CA_CERT",                          NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_CA_CERT_PASSWORD",                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_CA_CERT_PASSWORD_FLAGS",           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_CLIENT_CERT",                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_CLIENT_CERT_PASSWORD",             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_CLIENT_CERT_PASSWORD_FLAGS",       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_DOMAIN_MATCH",                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_DOMAIN_SUFFIX_MATCH",              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_EAP_METHODS",                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_FAST_PROVISIONING",                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_IDENTITY",                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_AUTH_METHODS",               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_CA_CERT",                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_CA_CERT_PASSWORD",           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_CA_CERT_PASSWORD_FLAGS",     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_CLIENT_CERT",                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_CLIENT_CERT_PASSWORD",       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_CLIENT_CERT_PASSWORD_FLAGS", NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_PRIVATE_KEY",                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD",       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD_FLAGS", NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_OPTIONAL",                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PAC_FILE",                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PASSWORD",                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PASSWORD_FLAGS",                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PASSWORD_RAW",                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PASSWORD_RAW_FLAGS",               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PEAP_FORCE_NEW_LABEL",             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PEAP_VERSION",                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PHASE1_AUTH_FLAGS",                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES",        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PHASE2_DOMAIN_MATCH",              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PHASE2_DOMAIN_SUFFIX_MATCH",       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PHASE2_SUBJECT_MATCH",             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PRIVATE_KEY",                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PRIVATE_KEY_PASSWORD",             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_PRIVATE_KEY_PASSWORD_FLAGS",       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_SUBJECT_MATCH",                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IEEE_8021X_SYSTEM_CA_CERTS",                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPADDR",                                      NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("IPV4_DHCP_TIMEOUT",                           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV4_DNS_PRIORITY",                           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV4_FAILURE_FATAL",                          NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV4_ROUTE_METRIC",                           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV4_ROUTE_TABLE",                            NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6ADDR",                                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6ADDR_SECONDARIES",                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6FORWARDING",                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6INIT",                                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6TUNNELIPV4",                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_ADDR_GEN_MODE",                          NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_AUTOCONF",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_DEFAULTDEV",                             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_DEFAULTGW",                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_DEFROUTE",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_DHCP_TIMEOUT",                           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_DISABLED",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_DNS_PRIORITY",                           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_DOMAIN",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_FAILURE_FATAL",                          NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_PEERDNS",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_PEERROUTES",                             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_PRIVACY",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_PRIVACY_PREFER_PUBLIC_IP",               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_RA_TIMEOUT",                             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_RES_OPTIONS",                            NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_ROUTE_METRIC",                           NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_ROUTE_TABLE",                            NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("IPV6_TOKEN",                                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("KEY",                                         NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("KEY_MGMT",                                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("KEY_PASSPHRASE",                              NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("KEY_TYPE",                                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("LLDP",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("LLMNR",                                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("MACADDR",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("MAC_ADDRESS_RANDOMIZATION",                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("MASTER",                                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("MASTER_UUID",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("MATCH_INTERFACE_NAME",                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("MDNS",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("METRIC",                                      NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("MODE",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("MTU",                                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("MULTI_CONNECT",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("MVRP",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("NAME",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("NETMASK",                                     NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("NETTYPE",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("NM_CONTROLLED",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN | NMS_IFCFG_KEY_TYPE_KEEP_WHEN_DIRTY ),
	_KEY_TYPE ("NM_USER_",                                    NMS_IFCFG_KEY_TYPE_IS_PREFIX ),
	_KEY_TYPE ("ONBOOT",                                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("OPTIONS",                                     NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("OVS_PORT",                                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("OVS_PORT_UUID",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PAC_SCRIPT",                                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PAC_URL",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PEERDNS",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PEERROUTES",                                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PHYSDEV",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PKEY",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PKEY_ID",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PMF",                                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PORTNAME",                                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("POWERSAVE",                                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("PREFIX",                                      NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("PROXY_METHOD",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("QDISC",                                       NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("REORDER_HDR",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("RES_OPTIONS",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("ROUTING_RULE6_",                              NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("ROUTING_RULE_",                               NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("SEARCH",                                      NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("SECONDARY_UUIDS",                             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("SECURITYMODE",                                NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("SLAVE",                                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("SRIOV_AUTOPROBE_DRIVERS",                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("SRIOV_TOTAL_VFS",                             NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("SRIOV_VF",                                    NMS_IFCFG_KEY_TYPE_IS_NUMBERED ),
	_KEY_TYPE ("SSID_HIDDEN",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("STABLE_ID",                                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("STP",                                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("SUBCHANNELS",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("TEAM_CONFIG",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("TEAM_MASTER",                                 NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("TEAM_MASTER_UUID",                            NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("TEAM_PORT_CONFIG",                            NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("TYPE",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("USERS",                                       NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("UUID",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("VLAN",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("VLAN_EGRESS_PRIORITY_MAP",                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("VLAN_FLAGS",                                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("VLAN_ID",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("VLAN_INGRESS_PRIORITY_MAP",                   NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("VRF",                                         NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("VRF_UUID",                                    NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("WEP_KEY_FLAGS",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("WPA_ALLOW_WPA",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("WPA_ALLOW_WPA2",                              NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("WPA_PSK",                                     NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("WPA_PSK_FLAGS",                               NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("WPS_METHOD",                                  NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
	_KEY_TYPE ("ZONE",                                        NMS_IFCFG_KEY_TYPE_IS_PLAIN ),
};

const NMSIfcfgKeyTypeInfo *
nms_ifcfg_well_known_key_find_info (const char *key, gssize *out_idx)
{
	gssize idx;

	G_STATIC_ASSERT (G_STRUCT_OFFSET (NMSIfcfgKeyTypeInfo, key_name) == 0);

	idx = nm_utils_array_find_binary_search (nms_ifcfg_well_known_keys,
	                                         sizeof (nms_ifcfg_well_known_keys[0]),
	                                         G_N_ELEMENTS (nms_ifcfg_well_known_keys),
	                                         &key,
	                                         nm_strcmp_p_with_data,
	                                         NULL);
	NM_SET_OUT (out_idx, idx);
	if (idx < 0)
		return NULL;
	return &nms_ifcfg_well_known_keys[idx];
}

const NMSIfcfgKeyTypeInfo *
nms_ifcfg_rh_utils_is_well_known_key (const char *key)
{
	const NMSIfcfgKeyTypeInfo *ti;
	gssize idx;

	nm_assert (key);

	ti = nms_ifcfg_well_known_key_find_info (key, &idx);

	if (ti) {
		if (NM_FLAGS_ANY (ti->key_flags,   NMS_IFCFG_KEY_TYPE_IS_PLAIN
		                                 | NMS_IFCFG_KEY_TYPE_IS_NUMBERED)) {
			/* These tags are valid on full match.
			 *
			 * Note that numbered tags we also treat as valid if they have no
			 * suffix. That is correct for "IPADDR", but less so for "ROUTING_RULE_". */
			return ti;
		}
		nm_assert (NM_FLAGS_HAS (ti->key_flags, NMS_IFCFG_KEY_TYPE_IS_PREFIX));
		/* a prefix tag needs some extra suffix afterwards to be valid. */
		return NULL;
	}

	/* Not found. Maybe it's a numbered/prefixed key? With idx we got the index where
	 * we should insert the key. Since the numbered/prefixed keys share a prefix, we can
	 * find the possible prefix at the index before the insert position. */
	idx = ~idx;
	if (idx == 0)
		return NULL;

	ti = &nms_ifcfg_well_known_keys[idx - 1];

	if (NM_FLAGS_HAS (ti->key_flags, NMS_IFCFG_KEY_TYPE_IS_NUMBERED)) {
		if (nms_ifcfg_rh_utils_is_numbered_tag (key, ti->key_name, NULL))
			return ti;
		return NULL;
	}

	if (NM_FLAGS_HAS (ti->key_flags, NMS_IFCFG_KEY_TYPE_IS_PREFIX)) {
		gsize l = strlen (ti->key_name);

		if (   strncmp (key, ti->key_name, l) == 0
		    && key[l] != '\0')
			return ti;
		return NULL;
	}

	return NULL;
}
