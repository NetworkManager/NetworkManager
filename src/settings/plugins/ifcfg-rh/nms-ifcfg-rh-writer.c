/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright 2009 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-ifcfg-rh-writer.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include "nm-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-8021x.h"
#include "nm-setting-proxy.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-vlan.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "nm-setting-metadata.h"

#include "nms-ifcfg-rh-common.h"
#include "nms-ifcfg-rh-reader.h"
#include "nms-ifcfg-rh-utils.h"
#include "shvar.h"

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_SETTINGS
#define _NMLOG_PREFIX_NAME "ifcfg-rh"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), (_NMLOG_DOMAIN), \
                "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                _NMLOG_PREFIX_NAME": " \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

static void
save_secret_flags (shvarFile *ifcfg,
                   const char *key,
                   NMSettingSecretFlags flags)
{
	GString *str;

	g_return_if_fail (ifcfg != NULL);
	g_return_if_fail (key != NULL);

	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
		svUnsetValue (ifcfg, key);
		return;
	}

	/* Convert flags bitfield into string representation */
	str = g_string_sized_new (20);
	if (flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)
		g_string_append (str, SECRET_FLAG_AGENT);

	if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED) {
		if (str->len)
			g_string_append_c (str, ' ');
		g_string_append (str, SECRET_FLAG_NOT_SAVED);
	}

	if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
		if (str->len)
			g_string_append_c (str, ' ');
		g_string_append (str, SECRET_FLAG_NOT_REQUIRED);
	}

	svSetValueStr (ifcfg, key, str->len ? str->str : NULL);
	g_string_free (str, TRUE);
}

static void
set_secret (shvarFile *ifcfg,
            const char *key,
            const char *value,
            const char *flags_key,
            NMSettingSecretFlags flags)
{
	shvarFile *keyfile;
	GError *error = NULL;

	/* Clear the secret from the ifcfg and the associated "keys" file */
	svUnsetValue (ifcfg, key);

	/* Save secret flags */
	save_secret_flags (ifcfg, flags_key, flags);

	keyfile = utils_get_keys_ifcfg (svFileGetName (ifcfg), TRUE);
	if (!keyfile) {
		_LOGW ("could not create ifcfg file for '%s'", svFileGetName (ifcfg));
		goto error;
	}

	/* Only write the secret if it's system owned and supposed to be saved */
	if (flags == NM_SETTING_SECRET_FLAG_NONE)
		svSetValueStr (keyfile, key, value);
	else
		svUnsetValue (keyfile, key);

	if (!svWriteFile (keyfile, 0600, &error)) {
		_LOGW ("could not update ifcfg file '%s': %s",
		       svFileGetName (keyfile), error->message);
		g_clear_error (&error);
		svCloseFile (keyfile);
		goto error;
	}
	svCloseFile (keyfile);
	return;

error:
	/* Try setting the secret in the actual ifcfg */
	svSetValueStr (ifcfg, key, value);
}

typedef struct {
	const NMSetting8021xSchemeVtable *vtable;
	const char *ifcfg_rh_key;
} Setting8021xSchemeVtable;

static const Setting8021xSchemeVtable setting_8021x_scheme_vtable[] = {
	[NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT] = {
		.vtable                 = &nm_setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT],
		.ifcfg_rh_key           = "IEEE_8021X_CA_CERT",
	},
	[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT] = {
		.vtable                 = &nm_setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT],
		.ifcfg_rh_key           = "IEEE_8021X_INNER_CA_CERT",
	},
	[NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT] = {
		.vtable                 = &nm_setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT],
		.ifcfg_rh_key           = "IEEE_8021X_CLIENT_CERT",
	},
	[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT] = {
		.vtable                 = &nm_setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT],
		.ifcfg_rh_key           = "IEEE_8021X_INNER_CLIENT_CERT",
	},
	[NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY] = {
		.vtable                 = &nm_setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY],
		.ifcfg_rh_key           = "IEEE_8021X_PRIVATE_KEY",
	},
	[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY] = {
		.vtable                 = &nm_setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY],
		.ifcfg_rh_key           = "IEEE_8021X_INNER_PRIVATE_KEY",
	},
};

static gboolean
write_object (NMSetting8021x *s_8021x,
              shvarFile *ifcfg,
              const Setting8021xSchemeVtable *objtype,
              GError **error)
{
	NMSetting8021xCKScheme scheme;
	const char *value = NULL;
	GBytes *blob = NULL;
	const char *password = NULL;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	char *secret_name, *secret_flags;
	const char *extension;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (objtype != NULL, FALSE);

	scheme = (*(objtype->vtable->scheme_func))(s_8021x);
	switch (scheme) {
	case NM_SETTING_802_1X_CK_SCHEME_UNKNOWN:
		break;
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		blob = (*(objtype->vtable->blob_func))(s_8021x);
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		value = (*(objtype->vtable->path_func))(s_8021x);
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		value = (*(objtype->vtable->uri_func))(s_8021x);
		break;
	default:
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Unhandled certificate object scheme");
		return FALSE;
	}

	/* Set the password for certificate/private key. */
	secret_name = g_strdup_printf ("%s_PASSWORD", objtype->ifcfg_rh_key);
	secret_flags = g_strdup_printf ("%s_PASSWORD_FLAGS", objtype->ifcfg_rh_key);
	password = (*(objtype->vtable->passwd_func))(s_8021x);
	flags = (*(objtype->vtable->pwflag_func))(s_8021x);
	set_secret (ifcfg, secret_name, password, secret_flags, flags);
	g_free (secret_name);
	g_free (secret_flags);

	if (!objtype->vtable->format_func)
		extension = "der";
	else if (objtype->vtable->format_func (s_8021x) == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
		extension = "p12";
	else
		extension = "pem";

	/* If certificate/private key wasn't sent, the connection may no longer be
	 * 802.1x and thus we clear out the paths and certs.
	 */
	if (!value && !blob) {
		char *standard_file;
		int ignored;

		/* Since no cert/private key is now being used, delete any standard file
		 * that was created for this connection, but leave other files alone.
		 * Thus, for example,
		 * /etc/sysconfig/network-scripts/ca-cert-Test_Write_Wifi_WPA_EAP-TLS.der
		 * will be deleted, but /etc/pki/tls/cert.pem will not.
		 */
		standard_file = utils_cert_path (svFileGetName (ifcfg), objtype->vtable->file_suffix, extension);
		if (g_file_test (standard_file, G_FILE_TEST_EXISTS))
			ignored = unlink (standard_file);
		g_free (standard_file);

		svUnsetValue (ifcfg, objtype->ifcfg_rh_key);
		return TRUE;
	}

	/* If the object path was specified, prefer that over any raw cert data that
	 * may have been sent.
	 */
	if (value) {
		svSetValueStr (ifcfg, objtype->ifcfg_rh_key, value);
		return TRUE;
	}

	/* If it's raw certificate data, write the data out to the standard file */
	if (blob) {
		gboolean success;
		char *new_file;
		GError *write_error = NULL;

		new_file = utils_cert_path (svFileGetName (ifcfg), objtype->vtable->file_suffix, extension);
		if (!new_file) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Could not create file path for %s / %s",
			             NM_SETTING_802_1X_SETTING_NAME, objtype->vtable->setting_key);
			return FALSE;
		}

		/* Write the raw certificate data out to the standard file so that we
		 * can use paths from now on instead of pushing around the certificate
		 * data itself.
		 */
		success = nm_utils_file_set_contents (new_file,
		                                      (const char *) g_bytes_get_data (blob, NULL),
		                                      g_bytes_get_size (blob),
		                                      0600,
		                                      &write_error);
		if (success) {
			svSetValueStr (ifcfg, objtype->ifcfg_rh_key, new_file);
			g_free (new_file);
			return TRUE;
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Could not write certificate/key for %s / %s: %s",
			             NM_SETTING_802_1X_SETTING_NAME, objtype->vtable->setting_key,
			             (write_error && write_error->message) ? write_error->message : "(unknown)");
			g_clear_error (&write_error);
		}
		g_free (new_file);
	}

	return FALSE;
}

static gboolean
write_8021x_certs (NMSetting8021x *s_8021x,
                   gboolean phase2,
                   shvarFile *ifcfg,
                   GError **error)
{
	const Setting8021xSchemeVtable *otype = NULL;

	/* CA certificate */
	if (!write_object (s_8021x, ifcfg,
	                   phase2
	                       ? &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT]
	                       : &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT],
	                   error))
		return FALSE;

	/* Private key */
	if (phase2)
		otype = &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY];
	else
		otype = &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY];

	/* Save the private key */
	if (!write_object (s_8021x, ifcfg, otype, error))
		return FALSE;

	/* Client certificate */
	if (otype->vtable->format_func (s_8021x) == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		/* Don't need a client certificate with PKCS#12 since the file is both
		 * the client certificate and the private key in one file.
		 */
		svSetValueStr (ifcfg,
		               phase2 ? "IEEE_8021X_INNER_CLIENT_CERT" : "IEEE_8021X_CLIENT_CERT",
		               NULL);
	} else {
		/* Save the client certificate */
		if (!write_object (s_8021x, ifcfg,
		                   phase2
		                       ? &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT]
		                       : &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT],
		                   error))
			return FALSE;
	}

	return TRUE;
}

static gboolean
write_8021x_setting (NMConnection *connection,
                     shvarFile *ifcfg,
                     gboolean wired,
                     GError **error)
{
	NMSetting8021x *s_8021x;
	NMSetting8021xAuthFlags auth_flags;
	const char *value, *match;
	char *tmp = NULL;
	GString *phase2_auth;
	GString *str;
	guint32 i, num;
	gint timeout;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	if (!s_8021x) {
		/* If wired, clear KEY_MGMT */
		if (wired)
			svUnsetValue (ifcfg, "KEY_MGMT");
		return TRUE;
	}

	/* If wired, write KEY_MGMT */
	if (wired)
		svSetValueStr (ifcfg, "KEY_MGMT", "IEEE8021X");

	/* EAP method */
	if (nm_setting_802_1x_get_num_eap_methods (s_8021x)) {
		value = nm_setting_802_1x_get_eap_method (s_8021x, 0);
		if (value)
			tmp = g_ascii_strup (value, -1);
	}
	svSetValueStr (ifcfg, "IEEE_8021X_EAP_METHODS", tmp);
	g_free (tmp);

	svSetValueStr (ifcfg, "IEEE_8021X_IDENTITY",
	               nm_setting_802_1x_get_identity (s_8021x));

	svSetValueStr (ifcfg, "IEEE_8021X_ANON_IDENTITY",
	               nm_setting_802_1x_get_anonymous_identity (s_8021x));

	set_secret (ifcfg,
	            "IEEE_8021X_PASSWORD",
	            nm_setting_802_1x_get_password (s_8021x),
	            "IEEE_8021X_PASSWORD_FLAGS",
	            nm_setting_802_1x_get_password_flags (s_8021x));

	/* PEAP version */
	value = nm_setting_802_1x_get_phase1_peapver (s_8021x);
	svUnsetValue (ifcfg, "IEEE_8021X_PEAP_VERSION");
	if (value && (!strcmp (value, "0") || !strcmp (value, "1")))
		svSetValueStr (ifcfg, "IEEE_8021X_PEAP_VERSION", value);

	/* Force new PEAP label */
	value = nm_setting_802_1x_get_phase1_peaplabel (s_8021x);
	svUnsetValue (ifcfg, "IEEE_8021X_PEAP_FORCE_NEW_LABEL");
	if (value && !strcmp (value, "1"))
		svSetValueStr (ifcfg, "IEEE_8021X_PEAP_FORCE_NEW_LABEL", "yes");

	/* PAC file */
	value = nm_setting_802_1x_get_pac_file (s_8021x);
	svUnsetValue (ifcfg, "IEEE_8021X_PAC_FILE");
	if (value)
		svSetValueStr (ifcfg, "IEEE_8021X_PAC_FILE", value);

	/* FAST PAC provisioning */
	value = nm_setting_802_1x_get_phase1_fast_provisioning (s_8021x);
	svUnsetValue (ifcfg, "IEEE_8021X_FAST_PROVISIONING");
	if (value) {
		if (strcmp (value, "1") == 0)
			svSetValueStr (ifcfg, "IEEE_8021X_FAST_PROVISIONING", "allow-unauth");
		else if (strcmp (value, "2") == 0)
			svSetValueStr (ifcfg, "IEEE_8021X_FAST_PROVISIONING", "allow-auth");
		else if (strcmp (value, "3") == 0)
			svSetValueStr (ifcfg, "IEEE_8021X_FAST_PROVISIONING", "allow-unauth allow-auth");
	}

	/* Phase2 auth methods */
	svUnsetValue (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS");
	phase2_auth = g_string_new (NULL);

	value = nm_setting_802_1x_get_phase2_auth (s_8021x);
	if (value) {
		tmp = g_ascii_strup (value, -1);
		g_string_append (phase2_auth, tmp);
		g_free (tmp);
	}

	value = nm_setting_802_1x_get_phase2_autheap (s_8021x);
	if (value) {
		if (phase2_auth->len)
			g_string_append_c (phase2_auth, ' ');

		tmp = g_ascii_strup (value, -1);
		g_string_append_printf (phase2_auth, "EAP-%s", tmp);
		g_free (tmp);
	}

	auth_flags = nm_setting_802_1x_get_phase1_auth_flags (s_8021x);
	if (auth_flags == NM_SETTING_802_1X_AUTH_FLAGS_NONE) {
		svUnsetValue (ifcfg, "IEEE_8021X_PHASE1_AUTH_FLAGS");
	} else {
		gs_free char *flags_str = NULL;

		flags_str = _nm_utils_enum_to_str_full (nm_setting_802_1x_auth_flags_get_type (),
		                                        auth_flags, " ");
		svSetValueStr (ifcfg, "IEEE_8021X_PHASE1_AUTH_FLAGS", flags_str);
	}

	svSetValueStr (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS",
	               phase2_auth->len ? phase2_auth->str : NULL);

	g_string_free (phase2_auth, TRUE);

	svSetValueStr (ifcfg, "IEEE_8021X_SUBJECT_MATCH",
	               nm_setting_802_1x_get_subject_match (s_8021x));

	svSetValueStr (ifcfg, "IEEE_8021X_PHASE2_SUBJECT_MATCH",
	               nm_setting_802_1x_get_phase2_subject_match (s_8021x));

	svUnsetValue (ifcfg, "IEEE_8021X_ALTSUBJECT_MATCHES");
	str = g_string_new (NULL);
	num = nm_setting_802_1x_get_num_altsubject_matches (s_8021x);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		match = nm_setting_802_1x_get_altsubject_match (s_8021x, i);
		g_string_append (str, match);
	}
	if (str->len > 0)
		svSetValueStr (ifcfg, "IEEE_8021X_ALTSUBJECT_MATCHES", str->str);
	g_string_free (str, TRUE);

	svUnsetValue (ifcfg, "IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES");
	str = g_string_new (NULL);
	num = nm_setting_802_1x_get_num_phase2_altsubject_matches (s_8021x);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		match = nm_setting_802_1x_get_phase2_altsubject_match (s_8021x, i);
		g_string_append (str, match);
	}
	if (str->len > 0)
		svSetValueStr (ifcfg, "IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES", str->str);
	g_string_free (str, TRUE);

	svSetValueStr (ifcfg, "IEEE_8021X_DOMAIN_SUFFIX_MATCH",
	               nm_setting_802_1x_get_domain_suffix_match (s_8021x));
	svSetValueStr (ifcfg, "IEEE_8021X_PHASE2_DOMAIN_SUFFIX_MATCH",
	               nm_setting_802_1x_get_phase2_domain_suffix_match (s_8021x));

	timeout = nm_setting_802_1x_get_auth_timeout (s_8021x);
	if (timeout > 0)
		svSetValueInt64 (ifcfg, "IEEE_8021X_AUTH_TIMEOUT", timeout);
	else
		svUnsetValue (ifcfg, "IEEE_8021X_AUTH_TIMEOUT");

	if (!write_8021x_certs (s_8021x, FALSE, ifcfg, error))
		return FALSE;

	/* phase2/inner certs */
	if (!write_8021x_certs (s_8021x, TRUE, ifcfg, error))
		return FALSE;

	return TRUE;
}

static gboolean
write_wireless_security_setting (NMConnection *connection,
                                 shvarFile *ifcfg,
                                 gboolean adhoc,
                                 gboolean *no_8021x,
                                 GError **error)
{
	NMSettingWirelessSecurity *s_wsec;
	const char *key_mgmt, *auth_alg, *key, *proto, *cipher;
	const char *psk = NULL;
	gboolean wep = FALSE, wpa = FALSE, dynamic_wep = FALSE;
	char *tmp;
	guint32 i, num;
	GString *str;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wsec) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
		return FALSE;
	}

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	g_assert (key_mgmt);

	auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);

	svUnsetValue (ifcfg, "DEFAULTKEY");

	if (!strcmp (key_mgmt, "none")) {
		svUnsetValue (ifcfg, "KEY_MGMT");
		wep = TRUE;
		*no_8021x = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-none") || !strcmp (key_mgmt, "wpa-psk")) {
		svSetValueStr (ifcfg, "KEY_MGMT", "WPA-PSK");
		wpa = TRUE;
		*no_8021x = TRUE;
	} else if (!strcmp (key_mgmt, "ieee8021x")) {
		svSetValueStr (ifcfg, "KEY_MGMT", "IEEE8021X");
		dynamic_wep = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-eap")) {
		svSetValueStr (ifcfg, "KEY_MGMT", "WPA-EAP");
		wpa = TRUE;
	}

	svUnsetValue (ifcfg, "SECURITYMODE");
	if (auth_alg) {
		if (!strcmp (auth_alg, "shared"))
			svSetValueStr (ifcfg, "SECURITYMODE", "restricted");
		else if (!strcmp (auth_alg, "open"))
			svSetValueStr (ifcfg, "SECURITYMODE", "open");
		else if (!strcmp (auth_alg, "leap")) {
			svSetValueStr (ifcfg, "SECURITYMODE", "leap");
			svSetValueStr (ifcfg, "IEEE_8021X_IDENTITY",
			               nm_setting_wireless_security_get_leap_username (s_wsec));
			set_secret (ifcfg,
			            "IEEE_8021X_PASSWORD",
			            nm_setting_wireless_security_get_leap_password (s_wsec),
			            "IEEE_8021X_PASSWORD_FLAGS",
			            nm_setting_wireless_security_get_leap_password_flags (s_wsec));
			*no_8021x = TRUE;
		}
	}

	/* WEP keys */

	/* Clear any default key */
	set_secret (ifcfg, "KEY", NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);

	/* Clear existing keys */
	for (i = 0; i < 4; i++) {
		tmp = g_strdup_printf ("KEY_PASSPHRASE%d", i + 1);
		set_secret (ifcfg, tmp, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
		g_free (tmp);

		tmp = g_strdup_printf ("KEY%d", i + 1);
		set_secret (ifcfg, tmp, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
		g_free (tmp);
	}

	/* And write the new ones out */
	if (wep) {
		/* Default WEP TX key index */
		tmp = g_strdup_printf ("%d", nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) + 1);
		svSetValueStr (ifcfg, "DEFAULTKEY", tmp);
		g_free (tmp);

		for (i = 0; i < 4; i++) {
			NMWepKeyType key_type;

			key = nm_setting_wireless_security_get_wep_key (s_wsec, i);
			if (key) {
				char *ascii_key = NULL;

				/* Passphrase needs a different ifcfg key since with WEP, there
				 * are some passphrases that are indistinguishable from WEP hex
				 * keys.
				 */
				key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
				if (key_type == NM_WEP_KEY_TYPE_UNKNOWN) {
					if (nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_KEY))
						key_type = NM_WEP_KEY_TYPE_KEY;
					else if (nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_PASSPHRASE))
						key_type = NM_WEP_KEY_TYPE_PASSPHRASE;
				}
				if (key_type == NM_WEP_KEY_TYPE_PASSPHRASE)
					tmp = g_strdup_printf ("KEY_PASSPHRASE%d", i + 1);
				else if (key_type == NM_WEP_KEY_TYPE_KEY) {
					tmp = g_strdup_printf ("KEY%d", i + 1);

					/* Add 's:' prefix for ASCII keys */
					if (strlen (key) == 5 || strlen (key) == 13) {
						ascii_key = g_strdup_printf ("s:%s", key);
						key = ascii_key;
					}
				} else {
					_LOGW ("invalid WEP key '%s'", key);
					tmp = NULL;
				}

				if (tmp) {
					set_secret (ifcfg,
					            tmp,
					            key,
					            "WEP_KEY_FLAGS",
					            nm_setting_wireless_security_get_wep_key_flags (s_wsec));
				}
				g_free (tmp);
				g_free (ascii_key);
			}
		}
	}

	/* WPA protos */
	svUnsetValue (ifcfg, "WPA_ALLOW_WPA");
	svUnsetValue (ifcfg, "WPA_ALLOW_WPA2");
	num = nm_setting_wireless_security_get_num_protos (s_wsec);
	for (i = 0; i < num; i++) {
		proto = nm_setting_wireless_security_get_proto (s_wsec, i);
		if (proto && !strcmp (proto, "wpa"))
			svSetValueStr (ifcfg, "WPA_ALLOW_WPA", "yes");
		else if (proto && !strcmp (proto, "rsn"))
			svSetValueStr (ifcfg, "WPA_ALLOW_WPA2", "yes");
	}

	/* WPA Pairwise ciphers */
	svUnsetValue (ifcfg, "CIPHER_PAIRWISE");
	str = g_string_new (NULL);
	num = nm_setting_wireless_security_get_num_pairwise (s_wsec);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		cipher = nm_setting_wireless_security_get_pairwise (s_wsec, i);

		/* Don't write out WEP40 or WEP104 if for some reason they are set; they
		 * are not valid pairwise ciphers.
		 */
		if (strcmp (cipher, "wep40") && strcmp (cipher, "wep104")) {
			tmp = g_ascii_strup (cipher, -1);
			g_string_append (str, tmp);
			g_free (tmp);
		}
	}
	if (strlen (str->str) && (dynamic_wep == FALSE))
		svSetValueStr (ifcfg, "CIPHER_PAIRWISE", str->str);
	g_string_free (str, TRUE);

	/* WPA Group ciphers */
	svUnsetValue (ifcfg, "CIPHER_GROUP");
	str = g_string_new (NULL);
	num = nm_setting_wireless_security_get_num_groups (s_wsec);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		cipher = nm_setting_wireless_security_get_group (s_wsec, i);
		tmp = g_ascii_strup (cipher, -1);
		g_string_append (str, tmp);
		g_free (tmp);
	}
	if (strlen (str->str) && (dynamic_wep == FALSE))
		svSetValueStr (ifcfg, "CIPHER_GROUP", str->str);
	g_string_free (str, TRUE);

	if (wpa)
		psk = nm_setting_wireless_security_get_psk (s_wsec);

	set_secret (ifcfg,
	            "WPA_PSK",
	            psk,
	            "WPA_PSK_FLAGS",
	            wpa ? nm_setting_wireless_security_get_psk_flags (s_wsec) : NM_SETTING_SECRET_FLAG_NONE);

	return TRUE;
}

static gboolean
write_wireless_setting (NMConnection *connection,
                        shvarFile *ifcfg,
                        gboolean *no_8021x,
                        GError **error)
{
	NMSettingWireless *s_wireless;
	char *tmp;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *mode, *bssid;
	const char *device_mac, *cloned_mac;
	guint32 mtu, chan, i;
	gboolean adhoc = FALSE, hex_ssid = FALSE;
	const char * const *macaddr_blacklist;

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (!s_wireless) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	device_mac = nm_setting_wireless_get_mac_address (s_wireless);
	svSetValueStr (ifcfg, "HWADDR", device_mac);

	cloned_mac = nm_setting_wireless_get_cloned_mac_address (s_wireless);
	svSetValueStr (ifcfg, "MACADDR", cloned_mac);

	svSetValueStr (ifcfg, "GENERATE_MAC_ADDRESS_MASK",
	               nm_setting_wireless_get_generate_mac_address_mask (s_wireless));

	svUnsetValue (ifcfg, "HWADDR_BLACKLIST");
	macaddr_blacklist = nm_setting_wireless_get_mac_address_blacklist (s_wireless);
	if (macaddr_blacklist[0]) {
		char *blacklist_str;

		blacklist_str = g_strjoinv (" ", (char **) macaddr_blacklist);
		svSetValueStr (ifcfg, "HWADDR_BLACKLIST", blacklist_str);
		g_free (blacklist_str);
	}

	svUnsetValue (ifcfg, "MTU");
	mtu = nm_setting_wireless_get_mtu (s_wireless);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		svSetValueStr (ifcfg, "MTU", tmp);
		g_free (tmp);
	}

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (!ssid) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing SSID in '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	if (!ssid_len || ssid_len > 32) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Invalid SSID in '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	/* If the SSID contains any non-printable characters, we need to use the
	 * hex notation of the SSID instead.
	 */
	if (   ssid_len > 2
	    && ssid_data[0] == '0'
	    && ssid_data[1] == 'x') {
		hex_ssid = TRUE;
		for (i = 2; i < ssid_len; i++) {
			if (!g_ascii_isxdigit (ssid_data[i])) {
				hex_ssid = FALSE;
				break;
			}
		}
	}
	if (!hex_ssid) {
		for (i = 0; i < ssid_len; i++) {
			if (!g_ascii_isprint (ssid_data[i])) {
				hex_ssid = TRUE;
				break;
			}
		}
	}

	if (hex_ssid) {
		GString *str;

		/* Hex SSIDs don't get quoted */
		str = g_string_sized_new (ssid_len * 2 + 3);
		g_string_append (str, "0x");
		for (i = 0; i < ssid_len; i++)
			g_string_append_printf (str, "%02X", ssid_data[i]);
		svSetValueStr (ifcfg, "ESSID", str->str);
		g_string_free (str, TRUE);
	} else {
		char buf[33];

		nm_assert (ssid_len <= 32);
		memcpy (buf, ssid_data, ssid_len);
		buf[ssid_len] = '\0';
		svSetValueStr (ifcfg, "ESSID", buf);
	}

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (!mode || !strcmp (mode, "infrastructure")) {
		svSetValueStr (ifcfg, "MODE", "Managed");
	} else if (!strcmp (mode, "adhoc")) {
		svSetValueStr (ifcfg, "MODE", "Ad-Hoc");
		adhoc = TRUE;
	} else if (!strcmp (mode, "ap")) {
		svSetValueStr (ifcfg, "MODE", "Ap");
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Invalid mode '%s' in '%s' setting",
		             mode, NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	svUnsetValue (ifcfg, "CHANNEL");
	svUnsetValue (ifcfg, "BAND");
	chan = nm_setting_wireless_get_channel (s_wireless);
	if (chan) {
		tmp = g_strdup_printf ("%u", chan);
		svSetValueStr (ifcfg, "CHANNEL", tmp);
		g_free (tmp);
	} else {
		/* Band only set if channel is not, since channel implies band */
		svSetValueStr (ifcfg, "BAND", nm_setting_wireless_get_band (s_wireless));
	}

	bssid = nm_setting_wireless_get_bssid (s_wireless);
	svSetValueStr (ifcfg, "BSSID", bssid);

	/* Ensure DEFAULTKEY and SECURITYMODE are cleared unless there's security;
	 * otherwise there's no way to detect WEP vs. open when WEP keys aren't
	 * saved.
	 */
	svUnsetValue (ifcfg, "DEFAULTKEY");
	svUnsetValue (ifcfg, "SECURITYMODE");

	if (nm_connection_get_setting_wireless_security (connection)) {
		if (!write_wireless_security_setting (connection, ifcfg, adhoc, no_8021x, error))
			return FALSE;
	} else {
		char *keys_path;

		/* Clear out wifi security keys */
		svUnsetValue (ifcfg, "KEY_MGMT");
		svUnsetValue (ifcfg, "IEEE_8021X_IDENTITY");
		set_secret (ifcfg, "IEEE_8021X_PASSWORD", NULL, "IEEE_8021X_PASSWORD_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
		svUnsetValue (ifcfg, "SECURITYMODE");

		/* Clear existing keys */
		set_secret (ifcfg, "KEY", NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
		for (i = 0; i < 4; i++) {
			tmp = g_strdup_printf ("KEY_PASSPHRASE%d", i + 1);
			set_secret (ifcfg, tmp, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
			g_free (tmp);

			tmp = g_strdup_printf ("KEY%d", i + 1);
			set_secret (ifcfg, tmp, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE);
			g_free (tmp);
		}

		svUnsetValue (ifcfg, "DEFAULTKEY");
		svUnsetValue (ifcfg, "WPA_ALLOW_WPA");
		svUnsetValue (ifcfg, "WPA_ALLOW_WPA2");
		svUnsetValue (ifcfg, "CIPHER_PAIRWISE");
		svUnsetValue (ifcfg, "CIPHER_GROUP");
		set_secret (ifcfg, "WPA_PSK", NULL, "WPA_PSK_FLAGS", NM_SETTING_SECRET_FLAG_NONE);

		/* Kill any old keys file */
		keys_path = utils_get_keys_path (svFileGetName (ifcfg));
		(void) unlink (keys_path);
		g_free (keys_path);
	}

	svSetValueStr (ifcfg, "SSID_HIDDEN", nm_setting_wireless_get_hidden (s_wireless) ? "yes" : NULL);

	switch (nm_setting_wireless_get_powersave (s_wireless)) {
	case NM_SETTING_WIRELESS_POWERSAVE_IGNORE:
		svSetValueStr (ifcfg, "POWERSAVE", "ignore");
		break;
	case NM_SETTING_WIRELESS_POWERSAVE_DISABLE:
		svSetValueStr (ifcfg, "POWERSAVE", "disable");
		break;
	case NM_SETTING_WIRELESS_POWERSAVE_ENABLE:
		svSetValueStr (ifcfg, "POWERSAVE", "enable");
		break;
	default:
	case NM_SETTING_WIRELESS_POWERSAVE_DEFAULT:
		svUnsetValue (ifcfg, "POWERSAVE");
		break;
	}

	switch (nm_setting_wireless_get_mac_address_randomization (s_wireless)) {
	case NM_SETTING_MAC_RANDOMIZATION_NEVER:
		svSetValueStr (ifcfg, "MAC_ADDRESS_RANDOMIZATION", "never");
		break;
	case NM_SETTING_MAC_RANDOMIZATION_ALWAYS:
		svSetValueStr (ifcfg, "MAC_ADDRESS_RANDOMIZATION", "always");
		break;
	case NM_SETTING_MAC_RANDOMIZATION_DEFAULT:
	default:
		svSetValueStr (ifcfg, "MAC_ADDRESS_RANDOMIZATION", "default");
		break;
	}

	svSetValueStr (ifcfg, "TYPE", TYPE_WIRELESS);

	return TRUE;
}

static gboolean
write_infiniband_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingInfiniband *s_infiniband;
	char *tmp;
	const char *mac, *transport_mode, *parent;
	guint32 mtu;
	int p_key;

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_INFINIBAND_SETTING_NAME);
		return FALSE;
	}

	mac = nm_setting_infiniband_get_mac_address (s_infiniband);
	svSetValueStr (ifcfg, "HWADDR", mac);

	svUnsetValue (ifcfg, "MTU");
	mtu = nm_setting_infiniband_get_mtu (s_infiniband);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		svSetValueStr (ifcfg, "MTU", tmp);
		g_free (tmp);
	}

	transport_mode = nm_setting_infiniband_get_transport_mode (s_infiniband);
	svSetValueBoolean (ifcfg, "CONNECTED_MODE", nm_streq (transport_mode, "connected"));

	p_key = nm_setting_infiniband_get_p_key (s_infiniband);
	if (p_key != -1) {
		svSetValueStr (ifcfg, "PKEY", "yes");
		tmp = g_strdup_printf ("%u", p_key);
		svSetValueStr (ifcfg, "PKEY_ID", tmp);
		g_free (tmp);

		parent = nm_setting_infiniband_get_parent (s_infiniband);
		if (parent)
			svSetValueStr (ifcfg, "PHYSDEV", parent);
	}

	svSetValueStr (ifcfg, "TYPE", TYPE_INFINIBAND);

	return TRUE;
}

static gboolean
write_wired_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingWired *s_wired;
	const char *device_mac, *cloned_mac;
	char *tmp;
	const char *nettype, *portname, *ctcprot, *s390_key, *s390_val, *duplex;
	guint32 mtu, num_opts, speed, i;
	const char *const *s390_subchannels;
	GString *str = NULL;
	const char * const *macaddr_blacklist;
	gboolean auto_negotiate;
	NMSettingWiredWakeOnLan wol;
	const char *wol_password;

	s_wired = nm_connection_get_setting_wired (connection);
	if (!s_wired) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_WIRED_SETTING_NAME);
		return FALSE;
	}

	device_mac = nm_setting_wired_get_mac_address (s_wired);
	svSetValueStr (ifcfg, "HWADDR", device_mac);

	cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	svSetValueStr (ifcfg, "MACADDR", cloned_mac);

	svSetValueStr (ifcfg, "GENERATE_MAC_ADDRESS_MASK",
	               nm_setting_wired_get_generate_mac_address_mask (s_wired));

	svUnsetValue (ifcfg, "HWADDR_BLACKLIST");
	macaddr_blacklist = nm_setting_wired_get_mac_address_blacklist (s_wired);
	if (macaddr_blacklist[0]) {
		char *blacklist_str;

		blacklist_str = g_strjoinv (" ", (char **) macaddr_blacklist);
		svSetValueStr (ifcfg, "HWADDR_BLACKLIST", blacklist_str);
		g_free (blacklist_str);
	}

	svUnsetValue (ifcfg, "MTU");
	mtu = nm_setting_wired_get_mtu (s_wired);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		svSetValueStr (ifcfg, "MTU", tmp);
		g_free (tmp);
	}

	svUnsetValue (ifcfg, "SUBCHANNELS");
	s390_subchannels = nm_setting_wired_get_s390_subchannels (s_wired);
	if (s390_subchannels) {
		int len = g_strv_length ((char **)s390_subchannels);

		tmp = NULL;
	    if (len == 2) {
		    tmp = g_strdup_printf ("%s,%s", s390_subchannels[0], s390_subchannels[1]);
	    } else if (len == 3) {
		    tmp = g_strdup_printf ("%s,%s,%s", s390_subchannels[0], s390_subchannels[1],
		                           s390_subchannels[2]);
		}
		svSetValueStr (ifcfg, "SUBCHANNELS", tmp);
		g_free (tmp);
	}

	svUnsetValue (ifcfg, "NETTYPE");
	nettype = nm_setting_wired_get_s390_nettype (s_wired);
	if (nettype)
		svSetValueStr (ifcfg, "NETTYPE", nettype);

	svUnsetValue (ifcfg, "PORTNAME");
	portname = nm_setting_wired_get_s390_option_by_key (s_wired, "portname");
	if (portname)
		svSetValueStr (ifcfg, "PORTNAME", portname);

	svUnsetValue (ifcfg, "CTCPROT");
	ctcprot = nm_setting_wired_get_s390_option_by_key (s_wired, "ctcprot");
	if (ctcprot)
		svSetValueStr (ifcfg, "CTCPROT", ctcprot);

	svUnsetValue (ifcfg, "OPTIONS");
	num_opts = nm_setting_wired_get_num_s390_options (s_wired);
	if (s390_subchannels && num_opts) {
		str = g_string_sized_new (30);
		for (i = 0; i < num_opts; i++) {
			nm_setting_wired_get_s390_option (s_wired, i, &s390_key, &s390_val);

			/* portname is handled separately */
			if (!strcmp (s390_key, "portname") || !strcmp (s390_key, "ctcprot"))
				continue;

			if (str->len)
				g_string_append_c (str, ' ');
			g_string_append_printf (str, "%s=%s", s390_key, s390_val);
		}
		if (str->len)
			svSetValueStr (ifcfg, "OPTIONS", str->str);
		g_string_free (str, TRUE);
	}

	/* Stuff ETHTOOL_OPT with required options */
	str = NULL;
	auto_negotiate = nm_setting_wired_get_auto_negotiate (s_wired);
	/* autoneg off + speed 0 + duplex NULL, means we want NM
	 * to skip link configuration which is default. So write
	 * down link config only if we have auto-negotiate true or
	 * a valid value for one among speed and duplex.
	 */
	if (auto_negotiate) {
		str = g_string_sized_new (64);
		g_string_printf (str, "autoneg on");
	} else {
		speed = nm_setting_wired_get_speed (s_wired);
		duplex = nm_setting_wired_get_duplex (s_wired);
		if (speed || duplex) {
			str = g_string_sized_new (64);
			g_string_printf (str, "autoneg off");
			if (speed)
				g_string_append_printf (str, " speed %u", speed);
			if (duplex)
				g_string_append_printf (str, " duplex %s", duplex);
		}
	}

	wol = nm_setting_wired_get_wake_on_lan (s_wired);
	wol_password = nm_setting_wired_get_wake_on_lan_password (s_wired);

	if (wol == NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE)
		svSetValue (ifcfg, "ETHTOOL_WAKE_ON_LAN", "ignore");
	else if (wol == NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT) {
		if (!str)
			svUnsetValue (ifcfg, "ETHTOOL_OPTS");
	} else {
		if (!str)
			str = g_string_sized_new (30);
		else
			g_string_append (str, " ");

		g_string_append (str, "wol ");

		if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_PHY))
			g_string_append (str, "p");
		if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST))
			g_string_append (str, "u");
		if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST))
			g_string_append (str, "m");
		if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST))
			g_string_append (str, "b");
		if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_ARP))
			g_string_append (str, "a");
		if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC))
			g_string_append (str, "g");

		if (!NM_FLAGS_ANY (wol, NM_SETTING_WIRED_WAKE_ON_LAN_ALL))
			g_string_append (str, "d");

		if (wol_password && NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC))
			g_string_append_printf (str, "s sopass %s", wol_password);
	}
	if (str) {
		svSetValueStr (ifcfg, "ETHTOOL_OPTS", str->str);
		g_string_free (str, TRUE);
	}
	/* End ETHTOOL_OPT stuffing */

	svSetValueStr (ifcfg, "TYPE", TYPE_ETHERNET);

	return TRUE;
}

static char *
vlan_priority_maplist_to_stringlist (NMSettingVlan *s_vlan, NMVlanPriorityMap map)
{
	char **strlist;
	char *value;

	if (map == NM_VLAN_INGRESS_MAP)
		g_object_get (G_OBJECT (s_vlan), NM_SETTING_VLAN_INGRESS_PRIORITY_MAP, &strlist, NULL);
	else if (map == NM_VLAN_EGRESS_MAP)
		g_object_get (G_OBJECT (s_vlan), NM_SETTING_VLAN_EGRESS_PRIORITY_MAP, &strlist, NULL);
	else
		return NULL;

	if (strlist[0])
		value = g_strjoinv (",", strlist);
	else
		value = NULL;
	g_strfreev (strlist);

	return value;
}

static gboolean
write_wired_for_virtual (NMConnection *connection, shvarFile *ifcfg)
{
	NMSettingWired *s_wired;
	gboolean has_wired = FALSE;

	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired) {
		const char *device_mac, *cloned_mac;
		char *tmp;
		guint32 mtu;

		has_wired = TRUE;

		device_mac = nm_setting_wired_get_mac_address (s_wired);
		svSetValueStr (ifcfg, "HWADDR", device_mac);

		cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
		svSetValueStr (ifcfg, "MACADDR", cloned_mac);

		svSetValueStr (ifcfg, "GENERATE_MAC_ADDRESS_MASK",
		               nm_setting_wired_get_generate_mac_address_mask (s_wired));

		mtu = nm_setting_wired_get_mtu (s_wired);
		if (mtu) {
			tmp = g_strdup_printf ("%u", mtu);
			svSetValueStr (ifcfg, "MTU", tmp);
			g_free (tmp);
		} else
			svUnsetValue (ifcfg, "MTU");
	}
	return has_wired;
}

static gboolean
write_vlan_setting (NMConnection *connection, shvarFile *ifcfg, gboolean *wired, GError **error)
{
	NMSettingVlan *s_vlan;
	NMSettingConnection *s_con;
	char *tmp;
	guint32 vlan_flags = 0;
	gsize s_buf_len;
	char s_buf[50], *s_buf_ptr;

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                     "Missing connection setting");
		return FALSE;
	}

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (!s_vlan) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                     "Missing VLAN setting");
		return FALSE;
	}

	svSetValueStr (ifcfg, "VLAN", "yes");
	svSetValueStr (ifcfg, "TYPE", TYPE_VLAN);
	svSetValueStr (ifcfg, "DEVICE", nm_setting_connection_get_interface_name (s_con));
	svSetValueStr (ifcfg, "PHYSDEV", nm_setting_vlan_get_parent (s_vlan));

	tmp = g_strdup_printf ("%d", nm_setting_vlan_get_id (s_vlan));
	svSetValueStr (ifcfg, "VLAN_ID", tmp);
	g_free (tmp);

	vlan_flags = nm_setting_vlan_get_flags (s_vlan);
	svSetValueBoolean (ifcfg, "REORDER_HDR", NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_REORDER_HEADERS));
	svSetValueBoolean (ifcfg, "GVRP", NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_GVRP));

	nm_utils_strbuf_init (s_buf, &s_buf_ptr, &s_buf_len);

	if (NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_LOOSE_BINDING))
		nm_utils_strbuf_append_str (&s_buf_ptr, &s_buf_len, "LOOSE_BINDING");
	if (!NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_REORDER_HEADERS))
		nm_utils_strbuf_append (&s_buf_ptr, &s_buf_len, "%sNO_REORDER_HDR", s_buf[0] ? "," : "");

	svSetValueStr (ifcfg, "VLAN_FLAGS", s_buf);

	svSetValueBoolean (ifcfg, "MVRP", NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_MVRP));

	tmp = vlan_priority_maplist_to_stringlist (s_vlan, NM_VLAN_INGRESS_MAP);
	svSetValueStr (ifcfg, "VLAN_INGRESS_PRIORITY_MAP", tmp);
	g_free (tmp);

	tmp = vlan_priority_maplist_to_stringlist (s_vlan, NM_VLAN_EGRESS_MAP);
	svSetValueStr (ifcfg, "VLAN_EGRESS_PRIORITY_MAP", tmp);
	g_free (tmp);

	svUnsetValue (ifcfg, "HWADDR");
	svUnsetValue (ifcfg, "MACADDR");
	svUnsetValue (ifcfg, "MTU");

	*wired = write_wired_for_virtual (connection, ifcfg);

	return TRUE;
}

static gboolean
write_bonding_setting (NMConnection *connection, shvarFile *ifcfg, gboolean *wired, GError **error)
{
	NMSettingBond *s_bond;
	const char *iface;
	guint32 i, num_opts;

	s_bond = nm_connection_get_setting_bond (connection);
	if (!s_bond) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_BOND_SETTING_NAME);
		return FALSE;
	}

	iface = nm_connection_get_interface_name (connection);
	if (!iface) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing interface name");
		return FALSE;
	}

	svSetValueStr (ifcfg, "DEVICE", iface);
	svUnsetValue (ifcfg, "BONDING_OPTS");

	num_opts = nm_setting_bond_get_num_options (s_bond);
	if (num_opts > 0) {
		GString *str = g_string_sized_new (64);

		for (i = 0; i < nm_setting_bond_get_num_options (s_bond); i++) {
			const char *key, *value;

			if (!nm_setting_bond_get_option (s_bond, i, &key, &value))
				continue;

			if (str->len)
				g_string_append_c (str, ' ');

			g_string_append_printf (str, "%s=%s", key, value);
		}

		if (str->len)
			svSetValueStr (ifcfg, "BONDING_OPTS", str->str);

		g_string_free (str, TRUE);
	}

	svSetValueStr (ifcfg, "TYPE", TYPE_BOND);
	svSetValueStr (ifcfg, "BONDING_MASTER", "yes");

	*wired = write_wired_for_virtual (connection, ifcfg);

	return TRUE;
}

static gboolean
write_team_setting (NMConnection *connection, shvarFile *ifcfg, gboolean *wired, GError **error)
{
	NMSettingTeam *s_team;
	const char *iface;
	const char *config;

	s_team = nm_connection_get_setting_team (connection);
	if (!s_team) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_TEAM_SETTING_NAME);
		return FALSE;
	}

	iface = nm_connection_get_interface_name (connection);
	if (!iface) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing interface name");
		return FALSE;
	}

	svSetValueStr (ifcfg, "DEVICE", iface);
	config = nm_setting_team_get_config (s_team);
	svSetValueStr (ifcfg, "TEAM_CONFIG", config);

	*wired = write_wired_for_virtual (connection, ifcfg);

	return TRUE;
}

static guint32
get_setting_default_uint (NMSetting *setting, const char *prop)
{
	GParamSpec *pspec;
	GValue val = G_VALUE_INIT;
	guint32 ret = 0;

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), prop);
	g_assert (pspec);
	g_value_init (&val, pspec->value_type);
	g_param_value_set_default (pspec, &val);
	g_assert (G_VALUE_HOLDS_UINT (&val));
	ret = g_value_get_uint (&val);
	g_value_unset (&val);
	return ret;
}

static gboolean
get_setting_default_boolean (NMSetting *setting, const char *prop)
{
	GParamSpec *pspec;
	GValue val = G_VALUE_INIT;
	gboolean ret = 0;

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), prop);
	g_assert (pspec);
	g_value_init (&val, pspec->value_type);
	g_param_value_set_default (pspec, &val);
	g_assert (G_VALUE_HOLDS_BOOLEAN (&val));
	ret = g_value_get_boolean (&val);
	g_value_unset (&val);
	return ret;
}

static gboolean
write_bridge_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingBridge *s_bridge;
	const char *iface;
	guint32 i;
	gboolean b;
	GString *opts;
	const char *mac;
	char *s;

	s_bridge = nm_connection_get_setting_bridge (connection);
	if (!s_bridge) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_BRIDGE_SETTING_NAME);
		return FALSE;
	}

	iface = nm_connection_get_interface_name (connection);
	if (!iface) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing interface name");
		return FALSE;
	}

	svSetValueStr (ifcfg, "DEVICE", iface);
	svUnsetValue (ifcfg, "BRIDGING_OPTS");
	svSetValueBoolean (ifcfg, "STP", FALSE);
	svUnsetValue (ifcfg, "DELAY");

	mac = nm_setting_bridge_get_mac_address (s_bridge);
	svSetValueStr (ifcfg, "MACADDR", mac);

	/* Bridge options */
	opts = g_string_sized_new (32);

	if (nm_setting_bridge_get_stp (s_bridge)) {
		svSetValueStr (ifcfg, "STP", "yes");

		i = nm_setting_bridge_get_forward_delay (s_bridge);
		if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_FORWARD_DELAY)) {
			s = g_strdup_printf ("%u", i);
			svSetValueStr (ifcfg, "DELAY", s);
			g_free (s);
		}

		g_string_append_printf (opts, "priority=%u", nm_setting_bridge_get_priority (s_bridge));

		i = nm_setting_bridge_get_hello_time (s_bridge);
		if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_HELLO_TIME)) {
			if (opts->len)
				g_string_append_c (opts, ' ');
			g_string_append_printf (opts, "hello_time=%u", i);
		}

		i = nm_setting_bridge_get_max_age (s_bridge);
		if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_MAX_AGE)) {
			if (opts->len)
				g_string_append_c (opts, ' ');
			g_string_append_printf (opts, "max_age=%u", i);
		}
	}

	i = nm_setting_bridge_get_ageing_time (s_bridge);
	if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_AGEING_TIME)) {
		if (opts->len)
			g_string_append_c (opts, ' ');
		g_string_append_printf (opts, "ageing_time=%u", i);
	}

	b = nm_setting_bridge_get_multicast_snooping (s_bridge);
	if (b != get_setting_default_boolean (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_MULTICAST_SNOOPING)) {
		if (opts->len)
			g_string_append_c (opts, ' ');
		g_string_append_printf (opts, "multicast_snooping=%u", (guint32) b);
	}

	if (opts->len)
		svSetValueStr (ifcfg, "BRIDGING_OPTS", opts->str);
	g_string_free (opts, TRUE);

	svSetValueStr (ifcfg, "TYPE", TYPE_BRIDGE);

	return TRUE;
}

static gboolean
write_bridge_port_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingBridgePort *s_port;
	guint32 i;
	GString *opts;

	s_port = nm_connection_get_setting_bridge_port (connection);
	if (!s_port)
		return TRUE;

	svUnsetValue (ifcfg, "BRIDGING_OPTS");

	/* Bridge options */
	opts = g_string_sized_new (32);

	i = nm_setting_bridge_port_get_priority (s_port);
	if (i != get_setting_default_uint (NM_SETTING (s_port), NM_SETTING_BRIDGE_PORT_PRIORITY))
		g_string_append_printf (opts, "priority=%u", i);

	i = nm_setting_bridge_port_get_path_cost (s_port);
	if (i != get_setting_default_uint (NM_SETTING (s_port), NM_SETTING_BRIDGE_PORT_PATH_COST)) {
		if (opts->len)
			g_string_append_c (opts, ' ');
		g_string_append_printf (opts, "path_cost=%u", i);
	}

	if (nm_setting_bridge_port_get_hairpin_mode (s_port)) {
		if (opts->len)
			g_string_append_c (opts, ' ');
		g_string_append_printf (opts, "hairpin_mode=1");
	}

	if (opts->len)
		svSetValueStr (ifcfg, "BRIDGING_OPTS", opts->str);
	g_string_free (opts, TRUE);

	return TRUE;
}

static gboolean
write_team_port_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingTeamPort *s_port;
	const char *config;

	s_port = nm_connection_get_setting_team_port (connection);
	if (!s_port)
		return TRUE;

	config = nm_setting_team_port_get_config (s_port);
	svSetValueStr (ifcfg, "TEAM_PORT_CONFIG", config);

	return TRUE;
}

static void
write_dcb_flags (shvarFile *ifcfg, const char *tag, NMSettingDcbFlags flags)
{
	char prop[NM_STRLEN ("DCB_xxxxxxxxxxxxxxxxxxxxxxx_yyyyyyyyyyyyyyyyyyyy")];

	nm_sprintf_buf (prop, "DCB_%s_ENABLE", tag);
	svSetValueStr (ifcfg, prop, (flags & NM_SETTING_DCB_FLAG_ENABLE) ? "yes" : NULL);

	nm_sprintf_buf (prop, "DCB_%s_ADVERTISE", tag);
	svSetValueStr (ifcfg, prop, (flags & NM_SETTING_DCB_FLAG_ADVERTISE) ? "yes" : NULL);

	nm_sprintf_buf (prop, "DCB_%s_WILLING", tag);
	svSetValueStr (ifcfg, prop, (flags & NM_SETTING_DCB_FLAG_WILLING) ? "yes" : NULL);
}

static void
write_dcb_app (shvarFile *ifcfg,
               const char *tag,
               NMSettingDcbFlags flags,
               gint priority)
{
	char prop[NM_STRLEN ("DCB_xxxxxxxxxxxxxxxxxxxxxxx_yyyyyyyyyyyyyyyyyyyy")];

	write_dcb_flags (ifcfg, tag, flags);

	nm_sprintf_buf (prop, "DCB_%s_PRIORITY", tag);
	if ((flags & NM_SETTING_DCB_FLAG_ENABLE) && (priority >= 0))
		svSetValueInt64 (ifcfg, prop, priority);
	else
		svUnsetValue (ifcfg, prop);
}

typedef gboolean (*DcbGetBoolFunc) (NMSettingDcb *, guint);

static void
write_dcb_bool_array (shvarFile *ifcfg,
                      const char *key,
                      NMSettingDcb *s_dcb,
                      NMSettingDcbFlags flags,
                      DcbGetBoolFunc get_func)
{
	char str[9];
	guint i;

	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE)) {
		svUnsetValue (ifcfg, key);
		return;
	}

	str[8] = 0;
	for (i = 0; i < 8; i++)
		str[i] = get_func (s_dcb, i) ? '1' : '0';
	svSetValueStr (ifcfg, key, str);
}

typedef guint (*DcbGetUintFunc) (NMSettingDcb *, guint);

static void
write_dcb_uint_array (shvarFile *ifcfg,
                      const char *key,
                      NMSettingDcb *s_dcb,
                      NMSettingDcbFlags flags,
                      DcbGetUintFunc get_func)
{
	char str[9];
	guint i, num;

	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE)) {
		svUnsetValue (ifcfg, key);
		return;
	}

	str[8] = 0;
	for (i = 0; i < 8; i++) {
		num = get_func (s_dcb, i);
		if (num < 10)
			str[i] = '0' + num;
		else if (num == 15)
			str[i] = 'f';
		else
			g_assert_not_reached ();
	}
	svSetValueStr (ifcfg, key, str);
}

static void
write_dcb_percent_array (shvarFile *ifcfg,
                         const char *key,
                         NMSettingDcb *s_dcb,
                         NMSettingDcbFlags flags,
                         DcbGetUintFunc get_func)
{
	GString *str;
	guint i;

	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE)) {
		svUnsetValue (ifcfg, key);
		return;
	}

	str = g_string_sized_new (30);
	for (i = 0; i < 8; i++) {
		if (str->len)
			g_string_append_c (str, ',');
		g_string_append_printf (str, "%d", get_func (s_dcb, i));
	}
	svSetValueStr (ifcfg, key, str->str);
	g_string_free (str, TRUE);
}

static gboolean
write_dcb_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingDcb *s_dcb;
	NMSettingDcbFlags flags;

	s_dcb = nm_connection_get_setting_dcb (connection);
	if (!s_dcb) {
		static const char *clear_keys[] = {
		    "DCB",
		    KEY_DCB_APP_FCOE_ENABLE,
		    KEY_DCB_APP_FCOE_ADVERTISE,
		    KEY_DCB_APP_FCOE_WILLING,
		    KEY_DCB_APP_FCOE_MODE,
		    KEY_DCB_APP_ISCSI_ENABLE,
		    KEY_DCB_APP_ISCSI_ADVERTISE,
		    KEY_DCB_APP_ISCSI_WILLING,
		    KEY_DCB_APP_FIP_ENABLE,
		    KEY_DCB_APP_FIP_ADVERTISE,
		    KEY_DCB_APP_FIP_WILLING,
		    KEY_DCB_PFC_ENABLE,
		    KEY_DCB_PFC_ADVERTISE,
		    KEY_DCB_PFC_WILLING,
		    KEY_DCB_PFC_UP,
		    KEY_DCB_PG_ENABLE,
		    KEY_DCB_PG_ADVERTISE,
		    KEY_DCB_PG_WILLING,
		    KEY_DCB_PG_ID,
		    KEY_DCB_PG_PCT,
		    KEY_DCB_PG_UPPCT,
		    KEY_DCB_PG_STRICT,
		    KEY_DCB_PG_UP2TC,
		    NULL };
		const char **iter;

		for (iter = clear_keys; *iter; iter++)
			svUnsetValue (ifcfg, *iter);
		return TRUE;
	}

	svSetValueStr (ifcfg, "DCB", "yes");

	write_dcb_app (ifcfg, "APP_FCOE",
	               nm_setting_dcb_get_app_fcoe_flags (s_dcb),
	               nm_setting_dcb_get_app_fcoe_priority (s_dcb));
	if (nm_setting_dcb_get_app_fcoe_flags (s_dcb) & NM_SETTING_DCB_FLAG_ENABLE)
		svSetValueStr (ifcfg, KEY_DCB_APP_FCOE_MODE, nm_setting_dcb_get_app_fcoe_mode (s_dcb));
	else
		svUnsetValue (ifcfg, KEY_DCB_APP_FCOE_MODE);

	write_dcb_app (ifcfg, "APP_ISCSI",
	               nm_setting_dcb_get_app_iscsi_flags (s_dcb),
	               nm_setting_dcb_get_app_iscsi_priority (s_dcb));
	write_dcb_app (ifcfg, "APP_FIP",
	               nm_setting_dcb_get_app_fip_flags (s_dcb),
	               nm_setting_dcb_get_app_fip_priority (s_dcb));

	write_dcb_flags (ifcfg, "PFC", nm_setting_dcb_get_priority_flow_control_flags (s_dcb));
	write_dcb_bool_array (ifcfg, KEY_DCB_PFC_UP, s_dcb,
	                      nm_setting_dcb_get_priority_flow_control_flags (s_dcb),
	                      nm_setting_dcb_get_priority_flow_control);

	flags = nm_setting_dcb_get_priority_group_flags (s_dcb);
	write_dcb_flags (ifcfg, "PG", flags);
	write_dcb_uint_array (ifcfg, KEY_DCB_PG_ID, s_dcb, flags, nm_setting_dcb_get_priority_group_id);
	write_dcb_percent_array (ifcfg, KEY_DCB_PG_PCT, s_dcb, flags, nm_setting_dcb_get_priority_group_bandwidth);
	write_dcb_percent_array (ifcfg, KEY_DCB_PG_UPPCT, s_dcb, flags, nm_setting_dcb_get_priority_bandwidth);
	write_dcb_bool_array (ifcfg, KEY_DCB_PG_STRICT, s_dcb, flags, nm_setting_dcb_get_priority_strict_bandwidth);
	write_dcb_uint_array (ifcfg, KEY_DCB_PG_UP2TC, s_dcb, flags, nm_setting_dcb_get_priority_traffic_class);

	return TRUE;
}

static void
write_connection_setting (NMSettingConnection *s_con, shvarFile *ifcfg)
{
	guint32 n, i;
	GString *str;
	const char *master, *master_iface = NULL, *type;
	char *tmp;
	gint i_int;

	svSetValueStr (ifcfg, "NAME", nm_setting_connection_get_id (s_con));
	svSetValueStr (ifcfg, "UUID", nm_setting_connection_get_uuid (s_con));
	svSetValueStr (ifcfg, "STABLE_ID", nm_setting_connection_get_stable_id (s_con));
	svSetValueStr (ifcfg, "DEVICE", nm_setting_connection_get_interface_name (s_con));
	svSetValueBoolean (ifcfg, "ONBOOT", nm_setting_connection_get_autoconnect (s_con));

	i_int = nm_setting_connection_get_autoconnect_priority (s_con);
	tmp = i_int != NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT
	      ? g_strdup_printf ("%d", i_int) : NULL;
	svSetValueStr (ifcfg, "AUTOCONNECT_PRIORITY", tmp);
	g_free (tmp);

	i_int = nm_setting_connection_get_autoconnect_retries (s_con);
	tmp = i_int != -1 ? g_strdup_printf ("%d", i_int) : NULL;
	svSetValueStr (ifcfg, "AUTOCONNECT_RETRIES", tmp);
	g_free (tmp);

	/* Only save the value for master connections */
	type = nm_setting_connection_get_connection_type (s_con);
	if (   !g_strcmp0 (type, NM_SETTING_BOND_SETTING_NAME)
	    || !g_strcmp0 (type, NM_SETTING_TEAM_SETTING_NAME)
	    || !g_strcmp0 (type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		NMSettingConnectionAutoconnectSlaves autoconnect_slaves;
		autoconnect_slaves = nm_setting_connection_get_autoconnect_slaves (s_con);
		svSetValueStr (ifcfg, "AUTOCONNECT_SLAVES",
		               autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_YES ? "yes" :
		               autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_NO ? "no" : NULL);
	} else
		svUnsetValue (ifcfg, "AUTOCONNECT_SLAVES");

	switch (nm_setting_connection_get_lldp (s_con)) {
	case NM_SETTING_CONNECTION_LLDP_ENABLE_RX:
		tmp = "rx";
		break;
	case NM_SETTING_CONNECTION_LLDP_DISABLE:
		tmp = "no";
		break;
	default:
		tmp = NULL;
	}
	svSetValueStr (ifcfg, "LLDP", tmp);

	/* Permissions */
	svUnsetValue (ifcfg, "USERS");
	n = nm_setting_connection_get_num_permissions (s_con);
	if (n > 0) {
		str = g_string_sized_new (n * 20);

		for (i = 0; i < n; i++) {
			const char *puser = NULL;

			/* Items separated by space for consistency with eg
			 * IPV6ADDR_SECONDARIES and DOMAIN.
			 */
			if (str->len)
				g_string_append_c (str, ' ');

			if (nm_setting_connection_get_permission (s_con, i, NULL, &puser, NULL))
				g_string_append (str, puser);
		}
		svSetValueStr (ifcfg, "USERS", str->str);
		g_string_free (str, TRUE);
	}

	svSetValueStr (ifcfg, "ZONE", nm_setting_connection_get_zone(s_con));

	svSetValueStr (ifcfg, "MASTER_UUID", NULL);
	svSetValueStr (ifcfg, "MASTER", NULL);
	svSetValueStr (ifcfg, "SLAVE", NULL);
	svSetValueStr (ifcfg, "BRIDGE_UUID", NULL);
	svSetValueStr (ifcfg, "BRIDGE", NULL);
	svSetValueStr (ifcfg, "TEAM_MASTER_UUID", NULL);
	svSetValueStr (ifcfg, "TEAM_MASTER", NULL);

	master = nm_setting_connection_get_master (s_con);
	if (master) {
		/* The reader prefers the *_UUID variants, however we still try to resolve
		 * it into an interface name, so that legacy tooling is not confused. */
		if (!nm_utils_get_testing ()) {
			/* This is conditional for easier testing. */
			master_iface = nm_manager_iface_for_uuid (nm_manager_get (), master);
		}
		if (!master_iface) {
			master_iface = master;
			master = NULL;

		}

		if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_BOND_SETTING_NAME)) {
			svSetValueStr (ifcfg, "MASTER_UUID", master);
			svSetValueStr (ifcfg, "MASTER", master_iface);
			svSetValueStr (ifcfg, "SLAVE", "yes");
		} else if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_BRIDGE_SETTING_NAME)) {
			svSetValueStr (ifcfg, "BRIDGE_UUID", master);
			svSetValueStr (ifcfg, "BRIDGE", master_iface);
		} else if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_TEAM_SETTING_NAME)) {
			svSetValueStr (ifcfg, "TEAM_MASTER_UUID", master);
			svSetValueStr (ifcfg, "TEAM_MASTER", master_iface);
			svUnsetValue (ifcfg, "TYPE");
		}
	}

	if (nm_streq0 (type, NM_SETTING_TEAM_SETTING_NAME))
		svSetValueStr (ifcfg, "DEVICETYPE", TYPE_TEAM);
	else if (master_iface && nm_setting_connection_is_slave_type (s_con, NM_SETTING_TEAM_SETTING_NAME))
		svSetValueStr (ifcfg, "DEVICETYPE", TYPE_TEAM_PORT);
	else
		svUnsetValue (ifcfg, "DEVICETYPE");

	/* secondary connection UUIDs */
	svUnsetValue (ifcfg, "SECONDARY_UUIDS");
	n = nm_setting_connection_get_num_secondaries (s_con);
	if (n > 0) {
		str = g_string_sized_new (n * 37);

		for (i = 0; i < n; i++) {
			const char *uuid;

			/* Items separated by space for consistency with eg
			 * IPV6ADDR_SECONDARIES and DOMAIN.
			 */
			if (str->len)
				g_string_append_c (str, ' ');

			if ((uuid = nm_setting_connection_get_secondary (s_con, i)) != NULL)
				g_string_append (str, uuid);
		}
		svSetValueStr (ifcfg, "SECONDARY_UUIDS", str->str);
		g_string_free (str, TRUE);
	}

	svUnsetValue (ifcfg, "GATEWAY_PING_TIMEOUT");
	if (nm_setting_connection_get_gateway_ping_timeout (s_con)) {
		tmp = g_strdup_printf ("%" G_GUINT32_FORMAT, nm_setting_connection_get_gateway_ping_timeout (s_con));
		svSetValueStr (ifcfg, "GATEWAY_PING_TIMEOUT", tmp);
		g_free (tmp);
	}

	switch (nm_setting_connection_get_metered (s_con)) {
	case NM_METERED_YES:
		svSetValueStr (ifcfg, "CONNECTION_METERED", "yes");
		break;
	case NM_METERED_NO:
		svSetValueStr (ifcfg, "CONNECTION_METERED", "no");
		break;
	default:
		svUnsetValue (ifcfg, "CONNECTION_METERED");
	}
}

static char *
get_route_attributes_string (NMIPRoute *route, int family)
{
	gs_strfreev char **names = NULL;
	GVariant *attr, *lock;
	GString *str;
	int i;

	names = nm_ip_route_get_attribute_names (route);
	if (!names || !names[0])
		return NULL;

	str = g_string_new ("");

	for (i = 0; names[i]; i++) {
		attr = nm_ip_route_get_attribute (route, names[i]);

		if (!nm_ip_route_attribute_validate (names[i], attr, family, NULL, NULL))
			continue;

		if (NM_IN_STRSET (names[i], NM_IP_ROUTE_ATTRIBUTE_WINDOW,
		                            NM_IP_ROUTE_ATTRIBUTE_CWND,
		                            NM_IP_ROUTE_ATTRIBUTE_INITCWND,
		                            NM_IP_ROUTE_ATTRIBUTE_INITRWND,
		                            NM_IP_ROUTE_ATTRIBUTE_MTU)) {
			char lock_name[256];

			nm_sprintf_buf (lock_name, "lock-%s", names[i]);
			lock = nm_ip_route_get_attribute (route, lock_name);

			g_string_append_printf (str,
			                        "%s %s%u",
			                        names[i],
			                        (lock && g_variant_get_boolean (lock)) ? "lock " : "",
			                        g_variant_get_uint32 (attr));
		} else if (strstr (names[i], "lock-")) {
			/* handled above */
		} else if (nm_streq (names[i], NM_IP_ROUTE_ATTRIBUTE_TOS)) {
			g_string_append_printf (str, "%s %u", names[i], (unsigned) g_variant_get_byte (attr));
		} else if (   nm_streq (names[i], NM_IP_ROUTE_ATTRIBUTE_PREF_SRC)
		           || nm_streq (names[i], NM_IP_ROUTE_ATTRIBUTE_SRC)) {
			char *arg = nm_streq (names[i], NM_IP_ROUTE_ATTRIBUTE_PREF_SRC) ? "src" : "from";

			g_string_append_printf (str, "%s %s", arg, g_variant_get_string (attr, NULL));
		} else {
			_LOGW ("unknown route option '%s'", names[i]);
			continue;
		}
		if (names[i + 1])
			g_string_append_c (str, ' ');
	}

	return g_string_free (str, FALSE);
}

static gboolean
write_route_file_legacy (const char *filename, NMSettingIPConfig *s_ip4, GError **error)
{
	const char *dest, *next_hop;
	char **route_items;
	gs_free char *route_contents = NULL;
	NMIPRoute *route;
	guint32 prefix;
	gint64 metric;
	guint32 i, num;

	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (s_ip4 != NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	num = nm_setting_ip_config_get_num_routes (s_ip4);
	if (num == 0) {
		unlink (filename);
		return TRUE;
	}

	route_items = g_malloc0 (sizeof (char*) * (num + 1));
	for (i = 0; i < num; i++) {
		gs_free char *options = NULL;

		route = nm_setting_ip_config_get_route (s_ip4, i);

		dest = nm_ip_route_get_dest (route);
		prefix = nm_ip_route_get_prefix (route);
		next_hop = nm_ip_route_get_next_hop (route);
		metric = nm_ip_route_get_metric (route);

		options = get_route_attributes_string (route, AF_INET);

		if (metric == -1) {
			route_items[i] = g_strdup_printf ("%s/%u via %s%s%s\n",
			                                  dest, prefix, next_hop,
			                                  options ? " " : "",
			                                  options ?: "");
		} else {
			route_items[i] = g_strdup_printf ("%s/%u via %s metric %u%s%s\n",
			                                  dest, prefix, next_hop, (guint32) metric,
			                                  options ? " " : "",
			                                  options ?: "");
		}
	}
	route_items[num] = NULL;
	route_contents = g_strjoinv (NULL, route_items);
	g_strfreev (route_items);

	if (!g_file_set_contents (filename, route_contents, -1, NULL)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Writing route file '%s' failed", filename);
		return FALSE;
	}

	return TRUE;
}

static gboolean
write_proxy_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingProxy *s_proxy;
	NMSettingProxyMethod method;
	const char *pac_url, *pac_script;

	s_proxy = nm_connection_get_setting_proxy (connection);
	if (!s_proxy)
		return TRUE;

	svUnsetValue (ifcfg, "BROWSER_ONLY");
	svUnsetValue (ifcfg, "PAC_URL");
	svUnsetValue (ifcfg, "PAC_SCRIPT");

	method = nm_setting_proxy_get_method (s_proxy);
	switch (method) {
	case NM_SETTING_PROXY_METHOD_AUTO:
		svSetValueStr (ifcfg, "PROXY_METHOD", "auto");

		pac_url = nm_setting_proxy_get_pac_url (s_proxy);
		if (pac_url)
			svSetValueStr (ifcfg, "PAC_URL", pac_url);

		pac_script = nm_setting_proxy_get_pac_script (s_proxy);
		if (pac_script)
			svSetValueStr (ifcfg, "PAC_SCRIPT", pac_script);

		break;
	case NM_SETTING_PROXY_METHOD_NONE:
		svSetValueStr (ifcfg, "PROXY_METHOD", "none");
		break;
	}

	svSetValueBoolean (ifcfg, "BROWSER_ONLY", nm_setting_proxy_get_browser_only (s_proxy));

	return TRUE;
}

static gboolean
write_ip4_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingIPConfig *s_ip4;
	const char *value;
	char *tmp;
	char addr_key[64];
	char prefix_key[64];
	char netmask_key[64];
	char gw_key[64];
	char *route_path = NULL;
	gint j;
	guint i, num, n;
	gint64 route_metric;
	gint priority;
	int timeout;
	GString *searches;
	const char *method = NULL;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4) {
		/* slave-type: clear IPv4 settings.
		 *
		 * Some IPv4 setting related options are not cleared,
		 * for no strong reason. */
		svUnsetValue (ifcfg, "BOOTPROTO");

		svUnsetValue (ifcfg, "IPADDR");
		svUnsetValue (ifcfg, "PREFIX");
		svUnsetValue (ifcfg, "NETMASK");
		svUnsetValue (ifcfg, "GATEWAY");

		svUnsetValue (ifcfg, "IPADDR0");
		svUnsetValue (ifcfg, "PREFIX0");
		svUnsetValue (ifcfg, "NETMASK0");
		svUnsetValue (ifcfg, "GATEWAY0");
		return TRUE;
	}

	method = nm_setting_ip_config_get_method (s_ip4);

	/* Missing IP4 setting is assumed to be DHCP */
	if (!method)
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		int result;

		/* IPv4 disabled, clear IPv4 related parameters */
		svUnsetValue (ifcfg, "BOOTPROTO");
		for (j = -1; j < 256; j++) {
			if (j == -1) {
				nm_sprintf_buf (addr_key, "IPADDR");
				nm_sprintf_buf (prefix_key, "PREFIX");
				nm_sprintf_buf (netmask_key, "NETMASK");
				nm_sprintf_buf (gw_key, "GATEWAY");
			} else {
				nm_sprintf_buf (addr_key, "IPADDR%d", (guint) j);
				nm_sprintf_buf (prefix_key, "PREFIX%u",  (guint) j);
				nm_sprintf_buf (netmask_key, "NETMASK%u",  (guint) j);
				nm_sprintf_buf (gw_key, "GATEWAY%u",  (guint) j);
			}

			svUnsetValue (ifcfg, addr_key);
			svUnsetValue (ifcfg, prefix_key);
			svUnsetValue (ifcfg, netmask_key);
			svUnsetValue (ifcfg, gw_key);
		}

		route_path = utils_get_route_path (svFileGetName (ifcfg));
		result = unlink (route_path);
		g_free (route_path);
		return TRUE;
	}

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO))
		svSetValueStr (ifcfg, "BOOTPROTO", "dhcp");
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
		svSetValueStr (ifcfg, "BOOTPROTO", "none");
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
		svSetValueStr (ifcfg, "BOOTPROTO", "autoip");
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
		svSetValueStr (ifcfg, "BOOTPROTO", "shared");

	/* Clear out un-numbered IP address fields */
	svUnsetValue (ifcfg, "IPADDR");
	svUnsetValue (ifcfg, "PREFIX");
	svUnsetValue (ifcfg, "NETMASK");
	svUnsetValue (ifcfg, "GATEWAY");
	/* Clear out zero-indexed IP address fields */
	svUnsetValue (ifcfg, "IPADDR0");
	svUnsetValue (ifcfg, "PREFIX0");
	svUnsetValue (ifcfg, "NETMASK0");
	svUnsetValue (ifcfg, "GATEWAY0");

	/* Write out IPADDR<n>, PREFIX<n>, GATEWAY<n> for current IP addresses
	 * without labels. Unset obsolete NETMASK<n>.
	 */
	num = nm_setting_ip_config_get_num_addresses (s_ip4);
	for (i = n = 0; i < num; i++) {
		NMIPAddress *addr;

		addr = nm_setting_ip_config_get_address (s_ip4, i);

		if (i > 0) {
			GVariant *label;

			label = nm_ip_address_get_attribute (addr, "label");
			if (label)
				continue;
		}

		if (n == 0) {
			/* Instead of index 0 use un-numbered variables.
			 * It's needed for compatibility with ifup that only recognizes 'GATEAWAY'
			 * See https://bugzilla.redhat.com/show_bug.cgi?id=771673
			 * and https://bugzilla.redhat.com/show_bug.cgi?id=1105770
			 */
			nm_sprintf_buf (addr_key, "IPADDR");
			nm_sprintf_buf (prefix_key, "PREFIX");
			nm_sprintf_buf (netmask_key, "NETMASK");
			nm_sprintf_buf (gw_key, "GATEWAY");
		} else {
			nm_sprintf_buf (addr_key, "IPADDR%u", n);
			nm_sprintf_buf (prefix_key, "PREFIX%u", n);
			nm_sprintf_buf (netmask_key, "NETMASK%u", n);
			nm_sprintf_buf (gw_key, "GATEWAY%u", n);
		}

		svSetValueStr (ifcfg, addr_key, nm_ip_address_get_address (addr));

		tmp = g_strdup_printf ("%u", nm_ip_address_get_prefix (addr));
		svSetValueStr (ifcfg, prefix_key, tmp);
		g_free (tmp);

		svUnsetValue (ifcfg, netmask_key);
		svUnsetValue (ifcfg, gw_key);
		n++;
	}

	/* Clear remaining IPADDR<n..255>, etc */
	for (i = n; i < 256; i++) {
		nm_sprintf_buf (addr_key, "IPADDR%u", i);
		nm_sprintf_buf (prefix_key, "PREFIX%u", i);
		nm_sprintf_buf (netmask_key, "NETMASK%u", i);
		nm_sprintf_buf (gw_key, "GATEWAY%u", i);

		svUnsetValue (ifcfg, addr_key);
		svUnsetValue (ifcfg, prefix_key);
		svUnsetValue (ifcfg, netmask_key);
		svUnsetValue (ifcfg, gw_key);
	}

	svSetValueStr (ifcfg, "GATEWAY", nm_setting_ip_config_get_gateway (s_ip4));

	num = nm_setting_ip_config_get_num_dns (s_ip4);
	for (i = 0; i < 254; i++) {
		const char *dns;

		nm_sprintf_buf (addr_key, "DNS%u", i + 1);
		if (i >= num)
			svUnsetValue (ifcfg, addr_key);
		else {
			dns = nm_setting_ip_config_get_dns (s_ip4, i);
			svSetValueStr (ifcfg, addr_key, dns);
		}
	}

	num = nm_setting_ip_config_get_num_dns_searches (s_ip4);
	if (num > 0) {
		searches = g_string_new (NULL);
		for (i = 0; i < num; i++) {
			if (i > 0)
				g_string_append_c (searches, ' ');
			g_string_append (searches, nm_setting_ip_config_get_dns_search (s_ip4, i));
		}
		svSetValueStr (ifcfg, "DOMAIN", searches->str);
		g_string_free (searches, TRUE);
	} else
		svUnsetValue (ifcfg, "DOMAIN");

	/* DEFROUTE; remember that it has the opposite meaning from never-default */
	svSetValueBoolean (ifcfg, "DEFROUTE", !nm_setting_ip_config_get_never_default (s_ip4));

	/* Missing PEERDNS means TRUE, so write it only when is FALSE */
	svSetValueStr (ifcfg, "PEERDNS",
	               nm_setting_ip_config_get_ignore_auto_dns (s_ip4) ? "no" : NULL);
	/* Missing PEERROUTES means TRUE, so write it only when is FALSE */
	svSetValueStr (ifcfg, "PEERROUTES",
	               nm_setting_ip_config_get_ignore_auto_routes (s_ip4) ? "no" : NULL);

	value = nm_setting_ip_config_get_dhcp_hostname (s_ip4);
	svSetValueStr (ifcfg, "DHCP_HOSTNAME", value);

	value = nm_setting_ip4_config_get_dhcp_fqdn (NM_SETTING_IP4_CONFIG (s_ip4));
	svSetValueStr (ifcfg, "DHCP_FQDN", value);

	/* Missing DHCP_SEND_HOSTNAME means TRUE, and we prefer not write it explicitly
	 * in that case, because it is NM-specific variable
	 */
	svSetValueStr (ifcfg, "DHCP_SEND_HOSTNAME",
	               nm_setting_ip_config_get_dhcp_send_hostname (s_ip4) ? NULL : "no");

	value = nm_setting_ip4_config_get_dhcp_client_id (NM_SETTING_IP4_CONFIG (s_ip4));
	svSetValueStr (ifcfg, "DHCP_CLIENT_ID", value);

	timeout = nm_setting_ip_config_get_dhcp_timeout (s_ip4);
	tmp = timeout ? g_strdup_printf ("%d", timeout) : NULL;
	svSetValueStr (ifcfg, "IPV4_DHCP_TIMEOUT", tmp);
	g_free (tmp);

	svSetValueBoolean (ifcfg, "IPV4_FAILURE_FATAL", !nm_setting_ip_config_get_may_fail (s_ip4));

	route_metric = nm_setting_ip_config_get_route_metric (s_ip4);
	tmp = route_metric != -1 ? g_strdup_printf ("%"G_GINT64_FORMAT, route_metric) : NULL;
	svSetValueStr (ifcfg, "IPV4_ROUTE_METRIC", tmp);
	g_free (tmp);

	/* Static routes - route-<name> file */
	route_path = utils_get_route_path (svFileGetName (ifcfg));
	if (!route_path) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not get route file path for '%s'", svFileGetName (ifcfg));
		return FALSE;
	}

	if (utils_has_route_file_new_syntax (route_path)) {
		shvarFile *routefile;

		routefile = utils_get_route_ifcfg (svFileGetName (ifcfg), TRUE);
		if (!routefile) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Could not create route file '%s'", route_path);
			g_free (route_path);
			return FALSE;
		}
		g_free (route_path);

		num = nm_setting_ip_config_get_num_routes (s_ip4);
		for (i = 0; i < 256; i++) {
			char buf[INET_ADDRSTRLEN];
			NMIPRoute *route;
			guint32 netmask;
			gint64 metric;
			char metric_key[64];
			char options_key[64];

			nm_sprintf_buf (addr_key, "ADDRESS%u", i);
			nm_sprintf_buf (netmask_key, "NETMASK%u", i);
			nm_sprintf_buf (gw_key, "GATEWAY%u", i);
			nm_sprintf_buf (metric_key, "METRIC%u", i);
			nm_sprintf_buf (options_key, "OPTIONS%u", i);

			if (i >= num) {
				svUnsetValue (routefile, addr_key);
				svUnsetValue (routefile, netmask_key);
				svUnsetValue (routefile, gw_key);
				svUnsetValue (routefile, metric_key);
				svUnsetValue (routefile, options_key);
			} else {
				gs_free char *options = NULL;

				route = nm_setting_ip_config_get_route (s_ip4, i);

				svSetValueStr (routefile, addr_key, nm_ip_route_get_dest (route));

				memset (buf, 0, sizeof (buf));
				netmask = nm_utils_ip4_prefix_to_netmask (nm_ip_route_get_prefix (route));
				inet_ntop (AF_INET, (const void *) &netmask, &buf[0], sizeof (buf));
				svSetValueStr (routefile, netmask_key, &buf[0]);

				svSetValueStr (routefile, gw_key, nm_ip_route_get_next_hop (route));

				memset (buf, 0, sizeof (buf));
				metric = nm_ip_route_get_metric (route);
				if (metric == -1)
					svUnsetValue (routefile, metric_key);
				else {
					tmp = g_strdup_printf ("%u", (guint32) metric);
					svSetValueStr (routefile, metric_key, tmp);
					g_free (tmp);
				}

				options = get_route_attributes_string (route, AF_INET);
				if (options)
					svSetValueStr (routefile, options_key, options);
			}
		}
		if (!svWriteFile (routefile, 0644, error)) {
			svCloseFile (routefile);
			return FALSE;
		}
		svCloseFile (routefile);
	} else {
		write_route_file_legacy (route_path, s_ip4, error);
		g_free (route_path);
		if (error && *error)
			return FALSE;
	}

	timeout = nm_setting_ip_config_get_dad_timeout (s_ip4);
	if (timeout < 0)
		svUnsetValue (ifcfg, "ARPING_WAIT");
	else if (timeout == 0)
		svSetValueStr (ifcfg, "ARPING_WAIT", "0");
	else {
		/* Round the value up to next integer */
		svSetValueInt64 (ifcfg, "ARPING_WAIT", (timeout - 1) / 1000 + 1);
	}

	priority = nm_setting_ip_config_get_dns_priority (s_ip4);
	if (priority)
		svSetValueInt64 (ifcfg, "IPV4_DNS_PRIORITY", priority);
	else
		svUnsetValue (ifcfg, "IPV4_DNS_PRIORITY");

	return TRUE;
}

static void
write_ip4_aliases (NMConnection *connection, char *base_ifcfg_path)
{
	NMSettingIPConfig *s_ip4;
	gs_free char *base_ifcfg_dir = NULL, *base_ifcfg_name = NULL;
	const char*base_name;
	int i, num, base_ifcfg_name_len, base_name_len;
	GDir *dir;

	base_ifcfg_dir = g_path_get_dirname (base_ifcfg_path);
	base_ifcfg_name = g_path_get_basename (base_ifcfg_path);
	base_ifcfg_name_len = strlen (base_ifcfg_name);
	if (!g_str_has_prefix (base_ifcfg_name, IFCFG_TAG))
		g_return_if_reached ();
	base_name = base_ifcfg_name + strlen (IFCFG_TAG);
	base_name_len = strlen (base_name);

	/* Remove all existing aliases for this file first */
	dir = g_dir_open (base_ifcfg_dir, 0, NULL);
	if (dir) {
		const char *item;

		while ((item = g_dir_read_name (dir))) {
			char *full_path;

			if (   strncmp (item, base_ifcfg_name, base_ifcfg_name_len) != 0
			    || item[base_ifcfg_name_len] != ':')
				continue;

			full_path = g_build_filename (base_ifcfg_dir, item, NULL);
			unlink (full_path);
			g_free (full_path);
		}

		g_dir_close (dir);
	}

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4) {
		/* slave-type: no alias files */
		return;
	}

	num = nm_setting_ip_config_get_num_addresses (s_ip4);
	for (i = 0; i < num; i++) {
		GVariant *label_var;
		const char *label, *p;
		char *path, *tmp;
		NMIPAddress *addr;
		shvarFile *ifcfg;

		addr = nm_setting_ip_config_get_address (s_ip4, i);

		label_var = nm_ip_address_get_attribute (addr, "label");
		if (!label_var)
			continue;
		label = g_variant_get_string (label_var, NULL);
		if (   strncmp (label, base_name, base_name_len) != 0
		    || label[base_name_len] != ':')
			continue;

		for (p = label; *p; p++) {
			if (!g_ascii_isalnum (*p) && *p != '_' && *p != ':')
				break;
		}
		if (*p)
			continue;

		path = g_strdup_printf ("%s%s", base_ifcfg_path, label + base_name_len);
		ifcfg = svCreateFile (path);
		g_free (path);

		svSetValueStr (ifcfg, "DEVICE", label);

		addr = nm_setting_ip_config_get_address (s_ip4, i);
		svSetValueStr (ifcfg, "IPADDR", nm_ip_address_get_address (addr));

		tmp = g_strdup_printf ("%u", nm_ip_address_get_prefix (addr));
		svSetValueStr (ifcfg, "PREFIX", tmp);
		g_free (tmp);

		svWriteFile (ifcfg, 0644, NULL);
		svCloseFile (ifcfg);
	}
}

static gboolean
write_route6_file (const char *filename, NMSettingIPConfig *s_ip6, GError **error)
{
	nm_auto_free_gstring GString *contents = NULL;
	NMIPRoute *route;
	guint32 i, num;

	g_return_val_if_fail (filename, FALSE);
	g_return_val_if_fail (s_ip6, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	num = nm_setting_ip_config_get_num_routes (s_ip6);
	if (num == 0) {
		unlink (filename);
		return TRUE;
	}

	contents = g_string_new ("");
	for (i = 0; i < num; i++) {
		gs_free char *options = NULL;

		route = nm_setting_ip_config_get_route (s_ip6, i);
		options = get_route_attributes_string (route, AF_INET6);

		if (nm_ip_route_get_metric (route) == -1) {
			g_string_append_printf (contents, "%s/%u via %s%s%s",
			                                  nm_ip_route_get_dest (route),
			                                  nm_ip_route_get_prefix (route),
			                                  nm_ip_route_get_next_hop (route),
			                                  options ? " " : "",
			                                  options ?: "");
		} else {
			g_string_append_printf (contents, "%s/%u via %s metric %u%s%s",
			                                  nm_ip_route_get_dest (route),
			                                  nm_ip_route_get_prefix (route),
			                                  nm_ip_route_get_next_hop (route),
			                                  (unsigned) nm_ip_route_get_metric (route),
			                                  options ? " " : "",
			                                  options ?: "");
		}
		g_string_append (contents, "\n");
	}

	if (!g_file_set_contents (filename, contents->str, -1, NULL)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Writing route6 file '%s' failed", filename);
		return FALSE;
	}

	return TRUE;
}

static void
write_ip6_setting_dhcp_hostname (NMSettingIPConfig *s_ip6, shvarFile *ifcfg)
{
	const char *hostname;

	hostname = nm_setting_ip_config_get_dhcp_hostname (s_ip6);
	svSetValueStr (ifcfg, "DHCPV6_HOSTNAME", hostname);

	/* Missing DHCPV6_SEND_HOSTNAME means TRUE, and we prefer not write it
	 * explicitly in that case, because it is NM-specific variable
	 */
	if (nm_setting_ip_config_get_dhcp_send_hostname (s_ip6))
		svUnsetValue (ifcfg, "DHCPV6_SEND_HOSTNAME");
	else
		svSetValueStr (ifcfg, "DHCPV6_SEND_HOSTNAME", "no");
}

static gboolean
write_ip6_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingIPConfig *s_ip6;
	NMSettingIPConfig *s_ip4;
	const char *value;
	char *tmp;
	guint i, num, num4;
	gint priority;
	NMIPAddress *addr;
	const char *dns;
	gint64 route_metric;
	GString *ip_str1, *ip_str2, *ip_ptr;
	char *route6_path;
	NMSettingIP6ConfigAddrGenMode addr_gen_mode;

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip6) {
		/* slave-type: clear IPv6 settings
		 *
		 * Some IPv6 setting related options are not cleared,
		 * for no strong reason. */
		svUnsetValue (ifcfg, "IPV6INIT");
		svUnsetValue (ifcfg, "IPV6_AUTOCONF");
		svUnsetValue (ifcfg, "DHCPV6C");
		svUnsetValue (ifcfg, "DHCPV6_HOSTNAME");
		svUnsetValue (ifcfg, "DHCPV6_SEND_HOSTNAME");
		svUnsetValue (ifcfg, "IPV6_DEFROUTE");
		svUnsetValue (ifcfg, "IPV6_PEERDNS");
		svUnsetValue (ifcfg, "IPV6_PEERROUTES");
		svUnsetValue (ifcfg, "IPV6_FAILURE_FATAL");
		svUnsetValue (ifcfg, "IPV6_ROUTE_METRIC");
		svUnsetValue (ifcfg, "IPV6_ADDR_GEN_MODE");
		return TRUE;
	}

	value = nm_setting_ip_config_get_method (s_ip6);
	g_assert (value);
	if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
		svSetValueStr (ifcfg, "IPV6INIT", "no");
		svUnsetValue (ifcfg, "DHCPV6C");
		return TRUE;
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
		svSetValueStr (ifcfg, "IPV6INIT", "yes");
		svSetValueStr (ifcfg, "IPV6_AUTOCONF", "yes");
		svUnsetValue (ifcfg, "DHCPV6C");
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
		svSetValueStr (ifcfg, "IPV6INIT", "yes");
		svSetValueStr (ifcfg, "IPV6_AUTOCONF", "no");
		svSetValueStr (ifcfg, "DHCPV6C", "yes");
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		svSetValueStr (ifcfg, "IPV6INIT", "yes");
		svSetValueStr (ifcfg, "IPV6_AUTOCONF", "no");
		svUnsetValue (ifcfg, "DHCPV6C");
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)) {
		svSetValueStr (ifcfg, "IPV6INIT", "yes");
		svSetValueStr (ifcfg, "IPV6_AUTOCONF", "no");
		svUnsetValue (ifcfg, "DHCPV6C");
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		svSetValueStr (ifcfg, "IPV6INIT", "yes");
		svSetValueStr (ifcfg, "IPV6_AUTOCONF", "shared");
		svUnsetValue (ifcfg, "DHCPV6C");
	}

	write_ip6_setting_dhcp_hostname (s_ip6, ifcfg);

	/* Write out IP addresses */
	num = nm_setting_ip_config_get_num_addresses (s_ip6);
	ip_str1 = g_string_new (NULL);
	ip_str2 = g_string_new (NULL);
	for (i = 0; i < num; i++) {
		if (i == 0)
			ip_ptr = ip_str1;
		else
			ip_ptr = ip_str2;

		addr = nm_setting_ip_config_get_address (s_ip6, i);

		if (i > 1)
			g_string_append_c (ip_ptr, ' ');  /* separate addresses in IPV6ADDR_SECONDARIES */
		g_string_append_printf (ip_ptr, "%s/%u",
		                        nm_ip_address_get_address (addr),
		                        nm_ip_address_get_prefix (addr));
	}
	svSetValueStr (ifcfg, "IPV6ADDR", ip_str1->str);
	svSetValueStr (ifcfg, "IPV6ADDR_SECONDARIES", ip_str2->str);
	svSetValueStr (ifcfg, "IPV6_DEFAULTGW", nm_setting_ip_config_get_gateway (s_ip6));
	g_string_free (ip_str1, TRUE);
	g_string_free (ip_str2, TRUE);

	/* Write out DNS - 'DNS' key is used both for IPv4 and IPv6 */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	num4 = s_ip4 ? nm_setting_ip_config_get_num_dns (s_ip4) : 0; /* from where to start with IPv6 entries */
	num = nm_setting_ip_config_get_num_dns (s_ip6);
	for (i = 0; i < 254; i++) {
		char addr_key[64];

		nm_sprintf_buf (addr_key, "DNS%u", i + num4 + 1);

		if (i >= num)
			svUnsetValue (ifcfg, addr_key);
		else {
			dns = nm_setting_ip_config_get_dns (s_ip6, i);
			svSetValueStr (ifcfg, addr_key, dns);
		}
	}

	/* Write out DNS domains - 'DOMAIN' key is shared for both IPv4 and IPv6 domains */
	num = nm_setting_ip_config_get_num_dns_searches (s_ip6);
	if (num > 0) {
		gs_free char *ip4_domains = NULL;
		nm_auto_free_gstring GString *searches = NULL;

		searches = g_string_new (svGetValueStr (ifcfg, "DOMAIN", &ip4_domains));
		for (i = 0; i < num; i++) {
			if (searches->len > 0)
				g_string_append_c (searches, ' ');
			g_string_append (searches, nm_setting_ip_config_get_dns_search (s_ip6, i));
		}
		svSetValueStr (ifcfg, "DOMAIN", searches->str);
	}


	/* handle IPV6_DEFROUTE */
	/* IPV6_DEFROUTE has the opposite meaning from 'never-default' */
	if (nm_setting_ip_config_get_never_default(s_ip6))
		svSetValueStr (ifcfg, "IPV6_DEFROUTE", "no");
	else
		svSetValueStr (ifcfg, "IPV6_DEFROUTE", "yes");

	svSetValueStr (ifcfg, "IPV6_PEERDNS",
	               nm_setting_ip_config_get_ignore_auto_dns (s_ip6) ? "no" : NULL);

	svSetValueStr (ifcfg, "IPV6_PEERROUTES",
	               nm_setting_ip_config_get_ignore_auto_routes (s_ip6) ? "no" : NULL);

	svSetValueStr (ifcfg, "IPV6_FAILURE_FATAL",
	               nm_setting_ip_config_get_may_fail (s_ip6) ? "no" : "yes");

	route_metric = nm_setting_ip_config_get_route_metric (s_ip6);
	tmp = route_metric != -1 ? g_strdup_printf ("%"G_GINT64_FORMAT, route_metric) : NULL;
	svSetValueStr (ifcfg, "IPV6_ROUTE_METRIC", tmp);
	g_free (tmp);

	/* IPv6 Privacy Extensions */
	svUnsetValue (ifcfg, "IPV6_PRIVACY");
	svUnsetValue (ifcfg, "IPV6_PRIVACY_PREFER_PUBLIC_IP");
	switch (nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (s_ip6))){
	case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
		svSetValueStr (ifcfg, "IPV6_PRIVACY", "no");
	break;
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
		svSetValueStr (ifcfg, "IPV6_PRIVACY", "rfc3041");
		svSetValueStr (ifcfg, "IPV6_PRIVACY_PREFER_PUBLIC_IP", "yes");
	break;
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
		svSetValueStr (ifcfg, "IPV6_PRIVACY", "rfc3041");
	break;
	default:
	break;
	}

	/* IPv6 Address generation mode */
	addr_gen_mode = nm_setting_ip6_config_get_addr_gen_mode (NM_SETTING_IP6_CONFIG (s_ip6));
	if (addr_gen_mode != NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64) {
		tmp = nm_utils_enum_to_str (nm_setting_ip6_config_addr_gen_mode_get_type (),
		                            addr_gen_mode);
		svSetValueStr (ifcfg, "IPV6_ADDR_GEN_MODE", tmp);
		g_free (tmp);
	} else {
		svUnsetValue (ifcfg, "IPV6_ADDR_GEN_MODE");
	}

	/* IPv6 tokenized interface identifier */
	value = nm_setting_ip6_config_get_token (NM_SETTING_IP6_CONFIG (s_ip6));
	svSetValueStr (ifcfg, "IPV6_TOKEN", value);

	priority = nm_setting_ip_config_get_dns_priority (s_ip6);
	if (priority)
		svSetValueInt64 (ifcfg, "IPV6_DNS_PRIORITY", priority);
	else
		svUnsetValue (ifcfg, "IPV6_DNS_PRIORITY");

	/* Static routes go to route6-<dev> file */
	route6_path = utils_get_route6_path (svFileGetName (ifcfg));
	if (!route6_path) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not get route6 file path for '%s'", svFileGetName (ifcfg));
		return FALSE;
	}
	write_route6_file (route6_path, s_ip6, error);
	g_free (route6_path);
	if (error && *error)
		return FALSE;

	return TRUE;
}

static void
add_dns_option (GPtrArray *array, const char *option)
{
	if (_nm_utils_dns_option_find_idx (array, option) < 0)
		g_ptr_array_add (array, (gpointer) option);
}

static gboolean
write_res_options (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingIPConfig *s_ip6;
	NMSettingIPConfig *s_ip4;
	const char *method;
	int i, num_options;
	gs_unref_ptrarray GPtrArray *array = NULL;
	GString *value;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);

	if (!s_ip4) {
		/* slave-type: clear res-options */
		svUnsetValue (ifcfg, "RES_OPTIONS");
		return TRUE;
	}

	array = g_ptr_array_new ();

	method = nm_setting_ip_config_get_method (s_ip4);
	if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		num_options = nm_setting_ip_config_get_num_dns_options (s_ip4);
		for (i = 0; i < num_options; i++)
			add_dns_option (array, nm_setting_ip_config_get_dns_option (s_ip4, i));
	}

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	method = nm_setting_ip_config_get_method (s_ip6);
	if (g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
		num_options = nm_setting_ip_config_get_num_dns_options (s_ip6);
		for (i = 0; i < num_options; i++)
			add_dns_option (array, nm_setting_ip_config_get_dns_option (s_ip6, i));
	}

	if (   array->len > 0
	    || nm_setting_ip_config_has_dns_options (s_ip4)
	    || nm_setting_ip_config_has_dns_options (s_ip6)) {
		value = g_string_new (NULL);
		for (i = 0; i < array->len; i++) {
			if (i > 0)
				g_string_append_c (value, ' ');
			g_string_append (value, array->pdata[i]);
		}
		svSetValue (ifcfg, "RES_OPTIONS", value->str);
		g_string_free (value, TRUE);
	} else
		svUnsetValue (ifcfg, "RES_OPTIONS");

	return TRUE;
}

static char *
escape_id (const char *id)
{
	char *escaped = g_strdup (id);
	char *p = escaped;

	/* Escape random stuff */
	while (*p) {
		if (*p == ' ')
			*p = '_';
		else if (strchr ("\\][|/=()!:", *p))
			*p = '-';
		p++;
	}

	return escaped;
}

static gboolean
write_connection (NMConnection *connection,
                  const char *ifcfg_dir,
                  const char *filename,
                  char **out_filename,
                  NMConnection **out_reread,
                  gboolean *out_reread_same,
                  GError **error)
{
	NMSettingConnection *s_con;
	nm_auto_shvar_file_close shvarFile *ifcfg = NULL;
	gs_free char *ifcfg_name = NULL;
	const char *type;
	gboolean no_8021x = FALSE;
	gboolean wired = FALSE;

	nm_assert (NM_IS_CONNECTION (connection));
	nm_assert (_nm_connection_verify (connection, NULL) == NM_SETTING_VERIFY_SUCCESS);
	nm_assert (!out_reread || !*out_reread);

	if (!writer_can_write_connection (connection, error))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (filename) {
		/* For existing connections, 'filename' should be full path to ifcfg file */
		ifcfg = svOpenFile (filename, error);
		if (!ifcfg)
			return FALSE;

		ifcfg_name = g_strdup (filename);
	} else {
		char *escaped;

		escaped = escape_id (nm_setting_connection_get_id (s_con));
		ifcfg_name = g_strdup_printf ("%s/ifcfg-%s", ifcfg_dir, escaped);

		/* If a file with this path already exists then we need another name.
		 * Multiple connections can have the same ID (ie if two connections with
		 * the same ID are visible to different users) but of course can't have
		 * the same path.
		 */
		if (g_file_test (ifcfg_name, G_FILE_TEST_EXISTS)) {
			guint32 idx = 0;

			nm_clear_g_free (&ifcfg_name);
			while (idx++ < 500) {
				ifcfg_name = g_strdup_printf ("%s/ifcfg-%s-%u", ifcfg_dir, escaped, idx);
				if (g_file_test (ifcfg_name, G_FILE_TEST_EXISTS) == FALSE)
					break;
				nm_clear_g_free (&ifcfg_name);
			}
		}
		g_free (escaped);

		if (ifcfg_name == NULL) {
			g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			                     "Failed to find usable ifcfg file name");
			return FALSE;
		}

		ifcfg = svCreateFile (ifcfg_name);
	}

	type = nm_setting_connection_get_connection_type (s_con);
	if (!type) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing connection type!");
		return FALSE;
	}

	if (!strcmp (type, NM_SETTING_WIRED_SETTING_NAME)) {
		// FIXME: can't write PPPoE at this time
		if (nm_connection_get_setting_pppoe (connection)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Can't write connection type '%s'",
			             NM_SETTING_PPPOE_SETTING_NAME);
			return FALSE;
		}

		if (!write_wired_setting (connection, ifcfg, error))
			return FALSE;
		wired = TRUE;
	} else if (!strcmp (type, NM_SETTING_VLAN_SETTING_NAME)) {
		if (!write_vlan_setting (connection, ifcfg, &wired, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		if (!write_wireless_setting (connection, ifcfg, &no_8021x, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		if (!write_infiniband_setting (connection, ifcfg, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_BOND_SETTING_NAME)) {
		if (!write_bonding_setting (connection, ifcfg, &wired, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_TEAM_SETTING_NAME)) {
		if (!write_team_setting (connection, ifcfg, &wired, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		if (!write_bridge_setting (connection, ifcfg, error))
			return FALSE;
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Can't write connection type '%s'", type);
		return FALSE;
	}

	if (!no_8021x) {
		if (!write_8021x_setting (connection, ifcfg, wired, error))
			return FALSE;
	}

	if (!write_bridge_port_setting (connection, ifcfg, error))
		return FALSE;

	if (!write_team_port_setting (connection, ifcfg, error))
		return FALSE;

	if (!write_dcb_setting (connection, ifcfg, error))
		return FALSE;

	if (!write_proxy_setting (connection, ifcfg, error))
		return FALSE;

	svUnsetValue (ifcfg, "DHCP_HOSTNAME");
	svUnsetValue (ifcfg, "DHCP_FQDN");

	if (!write_ip4_setting (connection, ifcfg, error))
		return FALSE;
	write_ip4_aliases (connection, ifcfg_name);

	if (!write_ip6_setting (connection, ifcfg, error))
		return FALSE;

	if (!write_res_options (connection, ifcfg, error))
		return FALSE;

	write_connection_setting (s_con, ifcfg);

	if (!svWriteFile (ifcfg, 0644, error))
		return FALSE;

	if (out_reread || out_reread_same) {
		gs_unref_object NMConnection *reread = NULL;
		gs_free_error GError *local = NULL;
		gs_free char *unhandled = NULL;
		gboolean reread_same = FALSE;

		reread = connection_from_file (ifcfg_name, &unhandled, &local, NULL);

		if (unhandled) {
			_LOGW ("failure to re-read the new connection from file \"%s\": %s",
			       ifcfg_name, "connection is unhandled");
			g_clear_object (&reread);
		} else if (!reread) {
			_LOGW ("failure to re-read the new connection from file \"%s\": %s",
			       ifcfg_name, local ? local->message : "<unknown>");
		} else {
			if (out_reread_same) {
				if (nm_connection_compare (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT))
					reread_same = TRUE;

				nm_assert (reread_same == nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));
				nm_assert (reread_same == ({
				                                gs_unref_hashtable GHashTable *_settings = NULL;

				                                (   nm_connection_diff (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT, &_settings)
				                                 && !_settings);
				                           }));
			}
		}

		NM_SET_OUT (out_reread, g_steal_pointer (&reread));
		NM_SET_OUT (out_reread_same, reread_same);
	}

	/* Only return the filename if this was a newly written ifcfg */
	if (out_filename && !filename)
		*out_filename = g_steal_pointer (&ifcfg_name);

	return TRUE;
}

gboolean
writer_can_write_connection (NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;

	if (   (   nm_connection_is_type (connection, NM_SETTING_WIRED_SETTING_NAME)
	        && !nm_connection_get_setting_pppoe (connection))
	    || nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_WIRELESS_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_BOND_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_TEAM_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_BRIDGE_SETTING_NAME))
		return TRUE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
	             "The ifcfg-rh plugin cannot write the connection '%s' (type '%s' pppoe %d)",
	             nm_connection_get_id (connection),
	             nm_setting_connection_get_connection_type (s_con),
	             !!nm_connection_get_setting_pppoe (connection));
	return FALSE;
}

gboolean
writer_new_connection (NMConnection *connection,
                       const char *ifcfg_dir,
                       char **out_filename,
                       NMConnection **out_reread,
                       gboolean *out_reread_same,
                       GError **error)
{
	return write_connection (connection, ifcfg_dir, NULL, out_filename, out_reread, out_reread_same, error);
}

gboolean
writer_update_connection (NMConnection *connection,
                          const char *ifcfg_dir,
                          const char *filename,
                          NMConnection **out_reread,
                          gboolean *out_reread_same,
                          GError **error)
{
	if (utils_has_complex_routes (filename)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Cannot modify a connection that has an associated 'rule-' or 'rule6-' file");
		return FALSE;
	}

	return write_connection (connection, ifcfg_dir, filename, NULL, out_reread, out_reread_same, error);
}

