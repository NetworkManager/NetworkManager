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
nms_ifcfg_rh_util_parse_unhandled_spec (const char *unhandled_spec,
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
	if ((len > tag_len) && !strcasecmp (base + len - tag_len, tag))
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
	char *contents = NULL;
	gsize len = 0;
	gboolean ret = FALSE;
	const char *pattern = "^[[:space:]]*ADDRESS[0-9]+=";

	g_return_val_if_fail (filename != NULL, TRUE);

	if (!g_file_get_contents (filename, &contents, &len, NULL))
		return TRUE;

	if (len <= 0) {
		ret = TRUE;
		goto gone;
	}

	if (g_regex_match_simple (pattern, contents, G_REGEX_MULTILINE, 0))
		ret = TRUE;

gone:
	g_free (contents);
	return ret;
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

const NMEthtoolData *
nms_ifcfg_rh_utils_get_ethtool_by_name (const char *name)
{
	static const struct {
		NMEthtoolID ethtool_id;
		const char *kernel_name;
	} kernel_names[] = {
		{ NM_ETHTOOL_ID_FEATURE_GRO,    "rx-gro" },
		{ NM_ETHTOOL_ID_FEATURE_GSO,    "tx-generic-segmentation" },
		{ NM_ETHTOOL_ID_FEATURE_LRO,    "rx-lro" },
		{ NM_ETHTOOL_ID_FEATURE_NTUPLE, "rx-ntuple-filter" },
		{ NM_ETHTOOL_ID_FEATURE_RX,     "rx-checksum" },
		{ NM_ETHTOOL_ID_FEATURE_RXHASH, "rx-hashing" },
		{ NM_ETHTOOL_ID_FEATURE_RXVLAN, "rx-vlan-hw-parse" },
		{ NM_ETHTOOL_ID_FEATURE_TXVLAN, "tx-vlan-hw-insert" },
	};
	guint i;

	for (i = 0; i < G_N_ELEMENTS (_nm_ethtool_ifcfg_names); i++) {
		if (nm_streq (name, _nm_ethtool_ifcfg_names[i]))
			return nm_ethtool_data[i];
	}

	/* Option not found. Note that ethtool utility has built-in features and
	 * NetworkManager's API follows the naming of these built-in features, whenever
	 * they exist.
	 * For example, NM's "ethtool.feature-ntuple" corresponds to ethtool utility's "ntuple"
	 * feature. However the underlying kernel feature is called "rx-ntuple-filter" (as reported
	 * for ETH_SS_FEATURES).
	 *
	 * With ethtool utility, whose command line we attempt to parse here, the user can also
	 * specify the name of the underlying kernel feature directly. So, check whether that is
	 * the case and if yes, map them to the corresponding NetworkManager's features. */
	for (i = 0; i < G_N_ELEMENTS (kernel_names); i++) {
		if (nm_streq (name, kernel_names[i].kernel_name))
			return nm_ethtool_data[kernel_names[i].ethtool_id];
	}

	return NULL;
}
