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

#include "config.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-8021x.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-vlan.h>
#include <nm-setting-team.h>
#include <nm-setting-team-port.h>
#include "nm-core-internal.h"
#include <nm-utils.h>
#include "nm-core-internal.h"

#include "nm-logging.h"
#include "gsystem-local-alloc.h"
#include "common.h"
#include "shvar.h"
#include "reader.h"
#include "writer.h"
#include "utils.h"
#include "crypto.h"


static void
save_secret_flags (shvarFile *ifcfg,
                   const char *key,
                   NMSettingSecretFlags flags)
{
	GString *str;

	g_return_if_fail (ifcfg != NULL);
	g_return_if_fail (key != NULL);

	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
		svSetValue (ifcfg, key, NULL, FALSE);
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

	svSetValue (ifcfg, key, str->len ? str->str : NULL, FALSE);
	g_string_free (str, TRUE);
}

static void
set_secret (shvarFile *ifcfg,
            const char *key,
            const char *value,
            const char *flags_key,
            NMSettingSecretFlags flags,
            gboolean verbatim)
{
	shvarFile *keyfile;
	GError *error = NULL;
	
	/* Clear the secret from the ifcfg and the associated "keys" file */
	svSetValue (ifcfg, key, NULL, FALSE);

	/* Save secret flags */
	save_secret_flags (ifcfg, flags_key, flags);

	keyfile = utils_get_keys_ifcfg (ifcfg->fileName, TRUE);
	if (!keyfile) {
		nm_log_warn (LOGD_SETTINGS, "    could not create ifcfg file for '%s'", ifcfg->fileName);
		goto error;
	}

	/* Clear the secret from the associated "keys" file */
	svSetValue (keyfile, key, NULL, FALSE);

	/* Only write the secret if it's system owned and supposed to be saved */
	if (flags == NM_SETTING_SECRET_FLAG_NONE)
		svSetValue (keyfile, key, value, verbatim);

	if (!svWriteFile (keyfile, 0600, &error)) {
		nm_log_warn (LOGD_SETTINGS, "    could not update ifcfg file '%s': %s",
		             keyfile->fileName, error->message);
		g_clear_error (&error);
		svCloseFile (keyfile);
		goto error;
	}
	svCloseFile (keyfile);
	return;

error:
	/* Try setting the secret in the actual ifcfg */
	svSetValue (ifcfg, key, value, FALSE);
}

static gboolean
write_secret_file (const char *path,
                   const char *data,
                   gsize len,
                   GError **error)
{
	char *tmppath;
	int fd = -1, written;
	gboolean success = FALSE;

	tmppath = g_malloc0 (strlen (path) + 10);
	memcpy (tmppath, path, strlen (path));
	strcat (tmppath, ".XXXXXX");

	errno = 0;
	fd = mkstemp (tmppath);
	if (fd < 0) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not create temporary file for '%s': %d",
		             path, errno);
		goto out;
	}

	/* Only readable by root */
	errno = 0;
	if (fchmod (fd, S_IRUSR | S_IWUSR)) {
		close (fd);
		unlink (tmppath);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not set permissions for temporary file '%s': %d",
		             path, errno);
		goto out;
	}

	errno = 0;
	written = write (fd, data, len);
	if (written != len) {
		close (fd);
		unlink (tmppath);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not write temporary file for '%s': %d",
		             path, errno);
		goto out;
	}
	close (fd);

	/* Try to rename */
	errno = 0;
	if (rename (tmppath, path)) {
		unlink (tmppath);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not rename temporary file to '%s': %d",
		             path, errno);
		goto out;
	}
	success = TRUE;

out:
	g_free (tmppath);
	return success;
}

typedef struct ObjectType {
	const char *setting_key;
	NMSetting8021xCKScheme (*scheme_func)(NMSetting8021x *setting);
	const char *           (*path_func)  (NMSetting8021x *setting);
	GBytes *               (*blob_func)  (NMSetting8021x *setting);
	const char *ifcfg_key;
	const char *suffix;
} ObjectType;

static const ObjectType ca_type = {
	NM_SETTING_802_1X_CA_CERT,
	nm_setting_802_1x_get_ca_cert_scheme,
	nm_setting_802_1x_get_ca_cert_path,
	nm_setting_802_1x_get_ca_cert_blob,
	"IEEE_8021X_CA_CERT",
	"ca-cert.der"
};

static const ObjectType phase2_ca_type = {
	NM_SETTING_802_1X_PHASE2_CA_CERT,
	nm_setting_802_1x_get_phase2_ca_cert_scheme,
	nm_setting_802_1x_get_phase2_ca_cert_path,
	nm_setting_802_1x_get_phase2_ca_cert_blob,
	"IEEE_8021X_INNER_CA_CERT",
	"inner-ca-cert.der"
};

static const ObjectType client_type = {
	NM_SETTING_802_1X_CLIENT_CERT,
	nm_setting_802_1x_get_client_cert_scheme,
	nm_setting_802_1x_get_client_cert_path,
	nm_setting_802_1x_get_client_cert_blob,
	"IEEE_8021X_CLIENT_CERT",
	"client-cert.der"
};

static const ObjectType phase2_client_type = {
	NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
	nm_setting_802_1x_get_phase2_client_cert_scheme,
	nm_setting_802_1x_get_phase2_client_cert_path,
	nm_setting_802_1x_get_phase2_client_cert_blob,
	"IEEE_8021X_INNER_CLIENT_CERT",
	"inner-client-cert.der"
};

static const ObjectType pk_type = {
	NM_SETTING_802_1X_PRIVATE_KEY,
	nm_setting_802_1x_get_private_key_scheme,
	nm_setting_802_1x_get_private_key_path,
	nm_setting_802_1x_get_private_key_blob,
	"IEEE_8021X_PRIVATE_KEY",
	"private-key.pem"
};

static const ObjectType phase2_pk_type = {
	NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	nm_setting_802_1x_get_phase2_private_key_scheme,
	nm_setting_802_1x_get_phase2_private_key_path,
	nm_setting_802_1x_get_phase2_private_key_blob,
	"IEEE_8021X_INNER_PRIVATE_KEY",
	"inner-private-key.pem"
};

static const ObjectType p12_type = {
	NM_SETTING_802_1X_PRIVATE_KEY,
	nm_setting_802_1x_get_private_key_scheme,
	nm_setting_802_1x_get_private_key_path,
	nm_setting_802_1x_get_private_key_blob,
	"IEEE_8021X_PRIVATE_KEY",
	"private-key.p12"
};

static const ObjectType phase2_p12_type = {
	NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	nm_setting_802_1x_get_phase2_private_key_scheme,
	nm_setting_802_1x_get_phase2_private_key_path,
	nm_setting_802_1x_get_phase2_private_key_blob,
	"IEEE_8021X_INNER_PRIVATE_KEY",
	"inner-private-key.p12"
};

static gboolean
write_object (NMSetting8021x *s_8021x,
              shvarFile *ifcfg,
              const ObjectType *objtype,
              GError **error)
{
	NMSetting8021xCKScheme scheme;
	const char *path = NULL;
	GBytes *blob = NULL;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (objtype != NULL, FALSE);

	scheme = (*(objtype->scheme_func))(s_8021x);
	switch (scheme) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		blob = (*(objtype->blob_func))(s_8021x);
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = (*(objtype->path_func))(s_8021x);
		break;
	default:
		break;
	}

	/* If certificate/private key wasn't sent, the connection may no longer be
	 * 802.1x and thus we clear out the paths and certs.
	 */
	if (!path && !blob) {
		char *standard_file;
		int ignored;

		/* Since no cert/private key is now being used, delete any standard file
		 * that was created for this connection, but leave other files alone.
		 * Thus, for example,
		 * /etc/sysconfig/network-scripts/ca-cert-Test_Write_Wifi_WPA_EAP-TLS.der
		 * will be deleted, but /etc/pki/tls/cert.pem will not.
		 */
		standard_file = utils_cert_path (ifcfg->fileName, objtype->suffix);
		if (g_file_test (standard_file, G_FILE_TEST_EXISTS))
			ignored = unlink (standard_file);
		g_free (standard_file);

		svSetValue (ifcfg, objtype->ifcfg_key, NULL, FALSE);
		return TRUE;
	}

	/* If the object path was specified, prefer that over any raw cert data that
	 * may have been sent.
	 */
	if (path) {
		svSetValue (ifcfg, objtype->ifcfg_key, path, FALSE);
		return TRUE;
	}

	/* If it's raw certificate data, write the data out to the standard file */
	if (blob) {
		gboolean success;
		char *new_file;
		GError *write_error = NULL;

		new_file = utils_cert_path (ifcfg->fileName, objtype->suffix);
		if (!new_file) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Could not create file path for %s / %s",
			             NM_SETTING_802_1X_SETTING_NAME, objtype->setting_key);
			return FALSE;
		}

		/* Write the raw certificate data out to the standard file so that we
		 * can use paths from now on instead of pushing around the certificate
		 * data itself.
		 */
		success = write_secret_file (new_file,
		                             (const char *) g_bytes_get_data (blob, NULL),
		                             g_bytes_get_size (blob),
		                             &write_error);
		if (success) {
			svSetValue (ifcfg, objtype->ifcfg_key, new_file, FALSE);
			g_free (new_file);
			return TRUE;
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Could not write certificate/key for %s / %s: %s",
			             NM_SETTING_802_1X_SETTING_NAME, objtype->setting_key,
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
	const char *password = NULL;
	gboolean success = FALSE, is_pkcs12 = FALSE;
	const ObjectType *otype = NULL;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	/* CA certificate */
	if (!write_object (s_8021x, ifcfg, phase2 ? &phase2_ca_type : &ca_type, error))
		return FALSE;

	/* Private key */
	if (phase2) {
		otype = &phase2_pk_type;
		if (nm_setting_802_1x_get_phase2_private_key_format (s_8021x) == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
			otype = &phase2_p12_type;
			is_pkcs12 = TRUE;
		}
		password = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
		flags = nm_setting_802_1x_get_phase2_private_key_password_flags (s_8021x);
	} else {
		otype = &pk_type;
		if (nm_setting_802_1x_get_private_key_format (s_8021x) == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
			otype = &p12_type;
			is_pkcs12 = TRUE;
		}
		password = nm_setting_802_1x_get_private_key_password (s_8021x);
		flags = nm_setting_802_1x_get_private_key_password_flags (s_8021x);
	}

	/* Save the private key */
	if (!write_object (s_8021x, ifcfg, otype, error))
		goto out;

	/* Private key password */
	if (phase2) {
		set_secret (ifcfg,
		            "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD",
		            password,
		            "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD_FLAGS",
		            flags,
		            FALSE);
	} else {
		set_secret (ifcfg,
		            "IEEE_8021X_PRIVATE_KEY_PASSWORD",
		            password,
		            "IEEE_8021X_PRIVATE_KEY_PASSWORD_FLAGS",
		            flags,
		            FALSE);
	}

	/* Client certificate */
	if (is_pkcs12) {
		/* Don't need a client certificate with PKCS#12 since the file is both
		 * the client certificate and the private key in one file.
		 */
		svSetValue (ifcfg,
		            phase2 ? "IEEE_8021X_INNER_CLIENT_CERT" : "IEEE_8021X_CLIENT_CERT",
		            NULL, FALSE);
	} else {
		/* Save the client certificate */
		if (!write_object (s_8021x, ifcfg, phase2 ? &phase2_client_type : &client_type, error))
			goto out;
	}

	success = TRUE;

out:
	return success;
}

static gboolean
write_8021x_setting (NMConnection *connection,
                     shvarFile *ifcfg,
                     gboolean wired,
                     GError **error)
{
	NMSetting8021x *s_8021x;
	const char *value, *match;
	char *tmp = NULL;
	gboolean success = FALSE;
	GString *phase2_auth;
	GString *str;
	guint32 i, num;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	if (!s_8021x) {
		/* If wired, clear KEY_MGMT */
		if (wired)
			svSetValue (ifcfg, "KEY_MGMT", NULL, FALSE);
		return TRUE;
	}

	/* If wired, write KEY_MGMT */
	if (wired)
		svSetValue (ifcfg, "KEY_MGMT", "IEEE8021X", FALSE);

	/* EAP method */
	if (nm_setting_802_1x_get_num_eap_methods (s_8021x)) {
		value = nm_setting_802_1x_get_eap_method (s_8021x, 0);
		if (value)
			tmp = g_ascii_strup (value, -1);
	}
	svSetValue (ifcfg, "IEEE_8021X_EAP_METHODS", tmp ? tmp : NULL, FALSE);
	g_free (tmp);

	svSetValue (ifcfg, "IEEE_8021X_IDENTITY",
	            nm_setting_802_1x_get_identity (s_8021x),
	            FALSE);

	svSetValue (ifcfg, "IEEE_8021X_ANON_IDENTITY",
	            nm_setting_802_1x_get_anonymous_identity (s_8021x),
	            FALSE);

	set_secret (ifcfg,
	            "IEEE_8021X_PASSWORD",
	            nm_setting_802_1x_get_password (s_8021x),
	            "IEEE_8021X_PASSWORD_FLAGS",
	            nm_setting_802_1x_get_password_flags (s_8021x),
	            FALSE);

	/* PEAP version */
	value = nm_setting_802_1x_get_phase1_peapver (s_8021x);
	svSetValue (ifcfg, "IEEE_8021X_PEAP_VERSION", NULL, FALSE);
	if (value && (!strcmp (value, "0") || !strcmp (value, "1")))
		svSetValue (ifcfg, "IEEE_8021X_PEAP_VERSION", value, FALSE);

	/* Force new PEAP label */
	value = nm_setting_802_1x_get_phase1_peaplabel (s_8021x);
	svSetValue (ifcfg, "IEEE_8021X_PEAP_FORCE_NEW_LABEL", NULL, FALSE);
	if (value && !strcmp (value, "1"))
		svSetValue (ifcfg, "IEEE_8021X_PEAP_FORCE_NEW_LABEL", "yes", FALSE);

	/* PAC file */
	value = nm_setting_802_1x_get_pac_file (s_8021x);
	svSetValue (ifcfg, "IEEE_8021X_PAC_FILE", NULL, FALSE);
	if (value)
		svSetValue (ifcfg, "IEEE_8021X_PAC_FILE", value, FALSE);

	/* FAST PAC provisioning */
	value = nm_setting_802_1x_get_phase1_fast_provisioning (s_8021x);
	svSetValue (ifcfg, "IEEE_8021X_FAST_PROVISIONING", NULL, FALSE);
	if (value) {
		if (strcmp (value, "1") == 0)
			svSetValue (ifcfg, "IEEE_8021X_FAST_PROVISIONING", "allow-unauth", FALSE);
		else if (strcmp (value, "2") == 0)
			svSetValue (ifcfg, "IEEE_8021X_FAST_PROVISIONING", "allow-auth", FALSE);
		else if (strcmp (value, "3") == 0)
			svSetValue (ifcfg, "IEEE_8021X_FAST_PROVISIONING", "allow-unauth allow-auth", FALSE);
	}

	/* Phase2 auth methods */
	svSetValue (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS", NULL, FALSE);
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

	svSetValue (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS",
	            phase2_auth->len ? phase2_auth->str : NULL,
	            FALSE);

	g_string_free (phase2_auth, TRUE);

	svSetValue (ifcfg, "IEEE_8021X_SUBJECT_MATCH",
	            nm_setting_802_1x_get_subject_match (s_8021x),
	            FALSE);

	svSetValue (ifcfg, "IEEE_8021X_PHASE2_SUBJECT_MATCH",
	            nm_setting_802_1x_get_phase2_subject_match (s_8021x),
	            FALSE);

	svSetValue (ifcfg, "IEEE_8021X_ALTSUBJECT_MATCHES", NULL, FALSE);
	str = g_string_new (NULL);
	num = nm_setting_802_1x_get_num_altsubject_matches (s_8021x);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		match = nm_setting_802_1x_get_altsubject_match (s_8021x, i);
		g_string_append (str, match);
	}
	if (str->len > 0)
		svSetValue (ifcfg, "IEEE_8021X_ALTSUBJECT_MATCHES", str->str, FALSE);
	g_string_free (str, TRUE);

	svSetValue (ifcfg, "IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES", NULL, FALSE);
	str = g_string_new (NULL);
	num = nm_setting_802_1x_get_num_phase2_altsubject_matches (s_8021x);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		match = nm_setting_802_1x_get_phase2_altsubject_match (s_8021x, i);
		g_string_append (str, match);
	}
	if (str->len > 0)
		svSetValue (ifcfg, "IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES", str->str, FALSE);
	g_string_free (str, TRUE);

	success = write_8021x_certs (s_8021x, FALSE, ifcfg, error);
	if (success) {
		/* phase2/inner certs */
		success = write_8021x_certs (s_8021x, TRUE, ifcfg, error);
	}

	return success;
}

static gboolean
write_wireless_security_setting (NMConnection *connection,
                                 shvarFile *ifcfg,
                                 gboolean adhoc,
                                 gboolean *no_8021x,
                                 GError **error)
{
	NMSettingWirelessSecurity *s_wsec;
	const char *key_mgmt, *auth_alg, *key, *proto, *cipher, *psk;
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

	svSetValue (ifcfg, "DEFAULTKEY", NULL, FALSE);

	if (!strcmp (key_mgmt, "none")) {
		svSetValue (ifcfg, "KEY_MGMT", NULL, FALSE);
		wep = TRUE;
		*no_8021x = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-none") || !strcmp (key_mgmt, "wpa-psk")) {
		svSetValue (ifcfg, "KEY_MGMT", "WPA-PSK", FALSE);
		wpa = TRUE;
		*no_8021x = TRUE;
	} else if (!strcmp (key_mgmt, "ieee8021x")) {
		svSetValue (ifcfg, "KEY_MGMT", "IEEE8021X", FALSE);
		dynamic_wep = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-eap")) {
		svSetValue (ifcfg, "KEY_MGMT", "WPA-EAP", FALSE);
		wpa = TRUE;
	}

	svSetValue (ifcfg, "SECURITYMODE", NULL, FALSE);
	if (auth_alg) {
		if (!strcmp (auth_alg, "shared"))
			svSetValue (ifcfg, "SECURITYMODE", "restricted", FALSE);
		else if (!strcmp (auth_alg, "open"))
			svSetValue (ifcfg, "SECURITYMODE", "open", FALSE);
		else if (!strcmp (auth_alg, "leap")) {
			svSetValue (ifcfg, "SECURITYMODE", "leap", FALSE);
			svSetValue (ifcfg, "IEEE_8021X_IDENTITY",
			            nm_setting_wireless_security_get_leap_username (s_wsec),
			            FALSE);
			set_secret (ifcfg,
			            "IEEE_8021X_PASSWORD",
			            nm_setting_wireless_security_get_leap_password (s_wsec),
			            "IEEE_8021X_PASSWORD_FLAGS",
			            nm_setting_wireless_security_get_leap_password_flags (s_wsec),
			            FALSE);
			*no_8021x = TRUE;
		}
	}

	/* WEP keys */

	/* Clear any default key */
	set_secret (ifcfg, "KEY", NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE, FALSE);

	/* Clear existing keys */
	for (i = 0; i < 4; i++) {
		tmp = g_strdup_printf ("KEY_PASSPHRASE%d", i + 1);
		set_secret (ifcfg, tmp, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE, FALSE);
		g_free (tmp);

		tmp = g_strdup_printf ("KEY%d", i + 1);
		set_secret (ifcfg, tmp, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE, FALSE);
		g_free (tmp);
	}

	/* And write the new ones out */
	if (wep) {
		/* Default WEP TX key index */
		tmp = g_strdup_printf ("%d", nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) + 1);
		svSetValue (ifcfg, "DEFAULTKEY", tmp, FALSE);
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
				} else
					key = NULL;

				set_secret (ifcfg,
				            tmp,
				            key,
				            "WEP_KEY_FLAGS",
				            nm_setting_wireless_security_get_wep_key_flags (s_wsec),
				            FALSE);
				g_free (tmp);
				g_free (ascii_key);
			}
		}
	}

	/* WPA protos */
	svSetValue (ifcfg, "WPA_ALLOW_WPA", NULL, FALSE);
	svSetValue (ifcfg, "WPA_ALLOW_WPA2", NULL, FALSE);
	num = nm_setting_wireless_security_get_num_protos (s_wsec);
	for (i = 0; i < num; i++) {
		proto = nm_setting_wireless_security_get_proto (s_wsec, i);
		if (proto && !strcmp (proto, "wpa"))
			svSetValue (ifcfg, "WPA_ALLOW_WPA", "yes", FALSE);
		else if (proto && !strcmp (proto, "rsn"))
			svSetValue (ifcfg, "WPA_ALLOW_WPA2", "yes", FALSE);
	}

	/* WPA Pairwise ciphers */
	svSetValue (ifcfg, "CIPHER_PAIRWISE", NULL, FALSE);
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
		svSetValue (ifcfg, "CIPHER_PAIRWISE", str->str, FALSE);
	g_string_free (str, TRUE);

	/* WPA Group ciphers */
	svSetValue (ifcfg, "CIPHER_GROUP", NULL, FALSE);
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
		svSetValue (ifcfg, "CIPHER_GROUP", str->str, FALSE);
	g_string_free (str, TRUE);

	/* WPA Passphrase */
	if (wpa) {
		char *quoted = NULL;

		psk = nm_setting_wireless_security_get_psk (s_wsec);
		if (psk && (strlen (psk) != 64)) {
			/* Quote the PSK since it's a passphrase */
			quoted = utils_single_quote_string (psk);
		}
		set_secret (ifcfg,
		            "WPA_PSK",
		            quoted ? quoted : psk,
		            "WPA_PSK_FLAGS",
		            nm_setting_wireless_security_get_psk_flags (s_wsec),
		            TRUE);
		g_free (quoted);
	} else {
		set_secret (ifcfg,
		            "WPA_PSK",
		            NULL,
		            "WPA_PSK_FLAGS",
		            NM_SETTING_SECRET_FLAG_NONE,
		            FALSE);
	}

	return TRUE;
}

static gboolean
write_wireless_setting (NMConnection *connection,
                        shvarFile *ifcfg,
                        gboolean *no_8021x,
                        GError **error)
{
	NMSettingWireless *s_wireless;
	char *tmp, *tmp2;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *mode, *bssid;
	const char *device_mac, *cloned_mac;
	char buf[33];
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
	svSetValue (ifcfg, "HWADDR", device_mac, FALSE);

	cloned_mac = nm_setting_wireless_get_cloned_mac_address (s_wireless);
	svSetValue (ifcfg, "MACADDR", cloned_mac, FALSE);

	svSetValue (ifcfg, "HWADDR_BLACKLIST", NULL, FALSE);
	macaddr_blacklist = nm_setting_wireless_get_mac_address_blacklist (s_wireless);
	if (macaddr_blacklist[0]) {
		char *blacklist_str;

		blacklist_str = g_strjoinv (" ", (char **) macaddr_blacklist);
		svSetValue (ifcfg, "HWADDR_BLACKLIST", blacklist_str, FALSE);
		g_free (blacklist_str);
	}

	svSetValue (ifcfg, "MTU", NULL, FALSE);
	mtu = nm_setting_wireless_get_mtu (s_wireless);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		svSetValue (ifcfg, "MTU", tmp, FALSE);
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
	for (i = 0; i < ssid_len; i++) {
		if (!g_ascii_isprint (ssid_data[i])) {
			hex_ssid = TRUE;
			break;
		}
	}

	if (hex_ssid) {
		GString *str;

		/* Hex SSIDs don't get quoted */
		str = g_string_sized_new (ssid_len * 2 + 3);
		g_string_append (str, "0x");
		for (i = 0; i < ssid_len; i++)
			g_string_append_printf (str, "%02X", ssid_data[i]);
		svSetValue (ifcfg, "ESSID", str->str, TRUE);
		g_string_free (str, TRUE);
	} else {
		/* Printable SSIDs always get quoted */
		memset (buf, 0, sizeof (buf));
		memcpy (buf, ssid_data, ssid_len);
		tmp = svEscape (buf);

		/* svEscape will usually quote the string, but just for consistency,
		 * if svEscape doesn't quote the ESSID, we quote it ourselves.
		 */
		if (tmp[0] != '"' && tmp[strlen (tmp) - 1] != '"') {
			tmp2 = g_strdup_printf ("\"%s\"", tmp);
			svSetValue (ifcfg, "ESSID", tmp2, TRUE);
			g_free (tmp2);
		} else
			svSetValue (ifcfg, "ESSID", tmp, TRUE);
		g_free (tmp);
	}

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (!mode || !strcmp (mode, "infrastructure")) {
		svSetValue (ifcfg, "MODE", "Managed", FALSE);
	} else if (!strcmp (mode, "adhoc")) {
		svSetValue (ifcfg, "MODE", "Ad-Hoc", FALSE);
		adhoc = TRUE;
	} else if (!strcmp (mode, "ap")) {
		svSetValue (ifcfg, "MODE", "Ap", FALSE);
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Invalid mode '%s' in '%s' setting",
		             mode, NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	svSetValue (ifcfg, "CHANNEL", NULL, FALSE);
	svSetValue (ifcfg, "BAND", NULL, FALSE);
	chan = nm_setting_wireless_get_channel (s_wireless);
	if (chan) {
		tmp = g_strdup_printf ("%u", chan);
		svSetValue (ifcfg, "CHANNEL", tmp, FALSE);
		g_free (tmp);
	} else {
		/* Band only set if channel is not, since channel implies band */
		svSetValue (ifcfg, "BAND", nm_setting_wireless_get_band (s_wireless), FALSE);
	}

	bssid = nm_setting_wireless_get_bssid (s_wireless);
	svSetValue (ifcfg, "BSSID", bssid, FALSE);

	/* Ensure DEFAULTKEY and SECURITYMODE are cleared unless there's security;
	 * otherwise there's no way to detect WEP vs. open when WEP keys aren't
	 * saved.
	 */
	svSetValue (ifcfg, "DEFAULTKEY", NULL, FALSE);
	svSetValue (ifcfg, "SECURITYMODE", NULL, FALSE);

	if (nm_connection_get_setting_wireless_security (connection)) {
		if (!write_wireless_security_setting (connection, ifcfg, adhoc, no_8021x, error))
			return FALSE;
	} else {
		char *keys_path;

		/* Clear out wifi security keys */
		svSetValue (ifcfg, "KEY_MGMT", NULL, FALSE);
		svSetValue (ifcfg, "IEEE_8021X_IDENTITY", NULL, FALSE);
		set_secret (ifcfg, "IEEE_8021X_PASSWORD", NULL, "IEEE_8021X_PASSWORD_FLAGS", NM_SETTING_SECRET_FLAG_NONE, FALSE);
		svSetValue (ifcfg, "SECURITYMODE", NULL, FALSE);

		/* Clear existing keys */
		set_secret (ifcfg, "KEY", NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE, FALSE);
		for (i = 0; i < 4; i++) {
			tmp = g_strdup_printf ("KEY_PASSPHRASE%d", i + 1);
			set_secret (ifcfg, tmp, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE, FALSE);
			g_free (tmp);
	
			tmp = g_strdup_printf ("KEY%d", i + 1);
			set_secret (ifcfg, tmp, NULL, "WEP_KEY_FLAGS", NM_SETTING_SECRET_FLAG_NONE, FALSE);
			g_free (tmp);
		}

		svSetValue (ifcfg, "DEFAULTKEY", NULL, FALSE);
		svSetValue (ifcfg, "WPA_ALLOW_WPA", NULL, FALSE);
		svSetValue (ifcfg, "WPA_ALLOW_WPA2", NULL, FALSE);
		svSetValue (ifcfg, "CIPHER_PAIRWISE", NULL, FALSE);
		svSetValue (ifcfg, "CIPHER_GROUP", NULL, FALSE);
		set_secret (ifcfg, "WPA_PSK", NULL, "WPA_PSK_FLAGS", NM_SETTING_SECRET_FLAG_NONE, FALSE);

		/* Kill any old keys file */
		keys_path = utils_get_keys_path (ifcfg->fileName);
		(void) unlink (keys_path);
		g_free (keys_path);
	}

	svSetValue (ifcfg, "SSID_HIDDEN", nm_setting_wireless_get_hidden (s_wireless) ? "yes" : NULL, TRUE);
	svSetValue (ifcfg, "POWERSAVE", nm_setting_wireless_get_powersave (s_wireless) ? "yes" : NULL, TRUE);

	svSetValue (ifcfg, "TYPE", TYPE_WIRELESS, FALSE);

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
	svSetValue (ifcfg, "HWADDR", mac, FALSE);

	svSetValue (ifcfg, "MTU", NULL, FALSE);
	mtu = nm_setting_infiniband_get_mtu (s_infiniband);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		svSetValue (ifcfg, "MTU", tmp, FALSE);
		g_free (tmp);
	}

	transport_mode = nm_setting_infiniband_get_transport_mode (s_infiniband);
	svSetValue (ifcfg, "CONNECTED_MODE",
	            strcmp (transport_mode, "connected") == 0 ? "yes" : "no",
	            FALSE);

	p_key = nm_setting_infiniband_get_p_key (s_infiniband);
	if (p_key != -1) {
		svSetValue (ifcfg, "PKEY", "yes", FALSE);
		tmp = g_strdup_printf ("%u", p_key);
		svSetValue (ifcfg, "PKEY_ID", tmp, FALSE);
		g_free (tmp);

		parent = nm_setting_infiniband_get_parent (s_infiniband);
		if (parent)
			svSetValue (ifcfg, "PHYSDEV", parent, FALSE);
	}

	svSetValue (ifcfg, "TYPE", TYPE_INFINIBAND, FALSE);

	return TRUE;
}

static gboolean
write_wired_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingWired *s_wired;
	const char *device_mac, *cloned_mac;
	char *tmp;
	const char *nettype, *portname, *ctcprot, *s390_key, *s390_val;
	guint32 mtu, num_opts, i;
	const char *const *s390_subchannels;
	GString *str;
	const char * const *macaddr_blacklist;

	s_wired = nm_connection_get_setting_wired (connection);
	if (!s_wired) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_WIRED_SETTING_NAME);
		return FALSE;
	}

	device_mac = nm_setting_wired_get_mac_address (s_wired);
	svSetValue (ifcfg, "HWADDR", device_mac, FALSE);

	cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	svSetValue (ifcfg, "MACADDR", cloned_mac, FALSE);

	svSetValue (ifcfg, "HWADDR_BLACKLIST", NULL, FALSE);
	macaddr_blacklist = nm_setting_wired_get_mac_address_blacklist (s_wired);
	if (macaddr_blacklist[0]) {
		char *blacklist_str;

		blacklist_str = g_strjoinv (" ", (char **) macaddr_blacklist);
		svSetValue (ifcfg, "HWADDR_BLACKLIST", blacklist_str, FALSE);
		g_free (blacklist_str);
	}

	svSetValue (ifcfg, "MTU", NULL, FALSE);
	mtu = nm_setting_wired_get_mtu (s_wired);
	if (mtu) {
		tmp = g_strdup_printf ("%u", mtu);
		svSetValue (ifcfg, "MTU", tmp, FALSE);
		g_free (tmp);
	}

	svSetValue (ifcfg, "SUBCHANNELS", NULL, FALSE);
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
		svSetValue (ifcfg, "SUBCHANNELS", tmp, FALSE);
		g_free (tmp);
	}

	svSetValue (ifcfg, "NETTYPE", NULL, FALSE);
	nettype = nm_setting_wired_get_s390_nettype (s_wired);
	if (nettype)
		svSetValue (ifcfg, "NETTYPE", nettype, FALSE);

	svSetValue (ifcfg, "PORTNAME", NULL, FALSE);
	portname = nm_setting_wired_get_s390_option_by_key (s_wired, "portname");
	if (portname)
		svSetValue (ifcfg, "PORTNAME", portname, FALSE);

	svSetValue (ifcfg, "CTCPROT", NULL, FALSE);
	ctcprot = nm_setting_wired_get_s390_option_by_key (s_wired, "ctcprot");
	if (ctcprot)
		svSetValue (ifcfg, "CTCPROT", ctcprot, FALSE);

	svSetValue (ifcfg, "OPTIONS", NULL, FALSE);
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
			svSetValue (ifcfg, "OPTIONS", str->str, FALSE);
		g_string_free (str, TRUE);
	}

	svSetValue (ifcfg, "TYPE", TYPE_ETHERNET, FALSE);

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
write_vlan_setting (NMConnection *connection, shvarFile *ifcfg, gboolean *wired, GError **error)
{
	NMSettingVlan *s_vlan;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	char *tmp;
	guint32 vlan_flags = 0;

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

	svSetValue (ifcfg, "VLAN", "yes", FALSE);
	svSetValue (ifcfg, "TYPE", TYPE_VLAN, FALSE);
	svSetValue (ifcfg, "DEVICE", nm_setting_connection_get_interface_name (s_con), FALSE);
	svSetValue (ifcfg, "PHYSDEV", nm_setting_vlan_get_parent (s_vlan), FALSE);

	tmp = g_strdup_printf ("%d", nm_setting_vlan_get_id (s_vlan));
	svSetValue (ifcfg, "VLAN_ID", tmp, FALSE);
	g_free (tmp);

	vlan_flags = nm_setting_vlan_get_flags (s_vlan);
	if (vlan_flags & NM_VLAN_FLAG_REORDER_HEADERS)
		svSetValue (ifcfg, "REORDER_HDR", "1", FALSE);
	else
		svSetValue (ifcfg, "REORDER_HDR", "0", FALSE);

	svSetValue (ifcfg, "VLAN_FLAGS", NULL, FALSE);
	if (vlan_flags & NM_VLAN_FLAG_GVRP) {
		if (vlan_flags & NM_VLAN_FLAG_LOOSE_BINDING)
			svSetValue (ifcfg, "VLAN_FLAGS", "GVRP,LOOSE_BINDING", FALSE);
		else
			svSetValue (ifcfg, "VLAN_FLAGS", "GVRP", FALSE);
	} else if (vlan_flags & NM_VLAN_FLAG_LOOSE_BINDING)
		svSetValue (ifcfg, "VLAN_FLAGS", "LOOSE_BINDING", FALSE);

	tmp = vlan_priority_maplist_to_stringlist (s_vlan, NM_VLAN_INGRESS_MAP);
	svSetValue (ifcfg, "VLAN_INGRESS_PRIORITY_MAP", tmp, FALSE);
	g_free (tmp);

	tmp = vlan_priority_maplist_to_stringlist (s_vlan, NM_VLAN_EGRESS_MAP);
	svSetValue (ifcfg, "VLAN_EGRESS_PRIORITY_MAP", tmp, FALSE);
	g_free (tmp);

	svSetValue (ifcfg, "HWADDR", NULL, FALSE);
	svSetValue (ifcfg, "MACADDR", NULL, FALSE);
	svSetValue (ifcfg, "MTU", NULL, FALSE);

	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired) {
		const char *device_mac, *cloned_mac;
		guint32 mtu;

		*wired = TRUE;

		device_mac = nm_setting_wired_get_mac_address (s_wired);
		if (device_mac)
			svSetValue (ifcfg, "HWADDR", device_mac, FALSE);

		cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
		if (cloned_mac)
			svSetValue (ifcfg, "MACADDR", cloned_mac, FALSE);

		mtu = nm_setting_wired_get_mtu (s_wired);
		if (mtu) {
			tmp = g_strdup_printf ("%u", mtu);
			svSetValue (ifcfg, "MTU", tmp, FALSE);
			g_free (tmp);
		}
	}

	return TRUE;
}

static gboolean
write_bonding_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
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

	svSetValue (ifcfg, "DEVICE", iface, FALSE);
	svSetValue (ifcfg, "BONDING_OPTS", NULL, FALSE);

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
			svSetValue (ifcfg, "BONDING_OPTS", str->str, FALSE);

		g_string_free (str, TRUE);
	}

	svSetValue (ifcfg, "TYPE", TYPE_BOND, FALSE);
	svSetValue (ifcfg, "BONDING_MASTER", "yes", FALSE);

	return TRUE;
}

static gboolean
write_team_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
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

	svSetValue (ifcfg, "DEVICE", iface, FALSE);
	config = nm_setting_team_get_config (s_team);
	svSetValue (ifcfg, "TEAM_CONFIG", config, FALSE);
	svSetValue (ifcfg, "DEVICETYPE", TYPE_TEAM, FALSE);

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

	svSetValue (ifcfg, "DEVICE", iface, FALSE);
	svSetValue (ifcfg, "BRIDGING_OPTS", NULL, FALSE);
	svSetValue (ifcfg, "STP", "no", FALSE);
	svSetValue (ifcfg, "DELAY", NULL, FALSE);

	mac = nm_setting_bridge_get_mac_address (s_bridge);
	svSetValue (ifcfg, "MACADDR", mac, FALSE);

	/* Bridge options */
	opts = g_string_sized_new (32);

	if (nm_setting_bridge_get_stp (s_bridge)) {
		svSetValue (ifcfg, "STP", "yes", FALSE);

		i = nm_setting_bridge_get_forward_delay (s_bridge);
		if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_FORWARD_DELAY)) {
			s = g_strdup_printf ("%u", i);
			svSetValue (ifcfg, "DELAY", s, FALSE);
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
		svSetValue (ifcfg, "BRIDGING_OPTS", opts->str, FALSE);
	g_string_free (opts, TRUE);

	svSetValue (ifcfg, "TYPE", TYPE_BRIDGE, FALSE);

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

	svSetValue (ifcfg, "BRIDGING_OPTS", NULL, FALSE);

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
		svSetValue (ifcfg, "BRIDGING_OPTS", opts->str, FALSE);
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
	svSetValue (ifcfg, "TEAM_PORT_CONFIG", config, FALSE);

	return TRUE;
}

static void
write_dcb_flags (shvarFile *ifcfg, const char *tag, NMSettingDcbFlags flags)
{
	char *prop;

	prop = g_strdup_printf ("DCB_%s_ENABLE", tag);
	svSetValue (ifcfg, prop, (flags & NM_SETTING_DCB_FLAG_ENABLE) ? "yes" : NULL, FALSE);
	g_free (prop);

	prop = g_strdup_printf ("DCB_%s_ADVERTISE", tag);
	svSetValue (ifcfg, prop, (flags & NM_SETTING_DCB_FLAG_ADVERTISE) ? "yes" : NULL, FALSE);
	g_free (prop);

	prop = g_strdup_printf ("DCB_%s_WILLING", tag);
	svSetValue (ifcfg, prop, (flags & NM_SETTING_DCB_FLAG_WILLING) ? "yes" : NULL, FALSE);
	g_free (prop);
}

static void
write_dcb_app (shvarFile *ifcfg,
               const char *tag,
               NMSettingDcbFlags flags,
               gint priority)
{
	char *prop, *tmp = NULL;

	write_dcb_flags (ifcfg, tag, flags);

	if ((flags & NM_SETTING_DCB_FLAG_ENABLE) && (priority >= 0))
		tmp = g_strdup_printf ("%d", priority);
	prop = g_strdup_printf ("DCB_%s_PRIORITY", tag);
	svSetValue (ifcfg, prop, tmp, FALSE);
	g_free (prop);
	g_free (tmp);
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
		svSetValue (ifcfg, key, NULL, FALSE);
		return;
	}

	str[8] = 0;
	for (i = 0; i < 8; i++)
		str[i] = get_func (s_dcb, i) ? '1' : '0';
	svSetValue (ifcfg, key, str, FALSE);
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
		svSetValue (ifcfg, key, NULL, FALSE);
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
	svSetValue (ifcfg, key, str, FALSE);
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
		svSetValue (ifcfg, key, NULL, FALSE);
		return;
	}

	str = g_string_sized_new (30);
	for (i = 0; i < 8; i++) {
		if (str->len)
			g_string_append_c (str, ',');
		g_string_append_printf (str, "%d", get_func (s_dcb, i));
	}
	svSetValue (ifcfg, key, str->str, FALSE);
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
			svSetValue (ifcfg, *iter, NULL, FALSE);
		return TRUE;
	}

	svSetValue (ifcfg, "DCB", "yes", FALSE);

	write_dcb_app (ifcfg, "APP_FCOE",
	               nm_setting_dcb_get_app_fcoe_flags (s_dcb),
	               nm_setting_dcb_get_app_fcoe_priority (s_dcb));
	if (nm_setting_dcb_get_app_fcoe_flags (s_dcb) & NM_SETTING_DCB_FLAG_ENABLE)
		svSetValue (ifcfg, KEY_DCB_APP_FCOE_MODE, nm_setting_dcb_get_app_fcoe_mode (s_dcb), FALSE);
	else
		svSetValue (ifcfg, KEY_DCB_APP_FCOE_MODE, NULL, FALSE);

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
	const char *master;
	char *tmp;
	gint i_int;

	svSetValue (ifcfg, "NAME", nm_setting_connection_get_id (s_con), FALSE);
	svSetValue (ifcfg, "UUID", nm_setting_connection_get_uuid (s_con), FALSE);
	svSetValue (ifcfg, "DEVICE", nm_setting_connection_get_interface_name (s_con), FALSE);
	svSetValue (ifcfg, "ONBOOT",
	            nm_setting_connection_get_autoconnect (s_con) ? "yes" : "no",
	            FALSE);

	i_int = nm_setting_connection_get_autoconnect_priority (s_con);
	tmp = i_int != NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT
	      ? g_strdup_printf ("%d", i_int) : NULL;
	svSetValue (ifcfg, "AUTOCONNECT_PRIORITY", tmp, FALSE);
	g_free (tmp);

	/* Permissions */
	svSetValue (ifcfg, "USERS", NULL, FALSE);
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
		svSetValue (ifcfg, "USERS", str->str, FALSE);
		g_string_free (str, TRUE);
	}

	svSetValue (ifcfg, "ZONE", nm_setting_connection_get_zone(s_con), FALSE);

	master = nm_setting_connection_get_master (s_con);
	if (master) {
		if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_BOND_SETTING_NAME)) {
			svSetValue (ifcfg, "MASTER", master, FALSE);
			svSetValue (ifcfg, "SLAVE", "yes", FALSE);
		} else if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_BRIDGE_SETTING_NAME))
			svSetValue (ifcfg, "BRIDGE", master, FALSE);
		else if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_TEAM_SETTING_NAME)) {
			svSetValue (ifcfg, "TEAM_MASTER", master, FALSE);
			svSetValue (ifcfg, "DEVICETYPE", TYPE_TEAM_PORT, FALSE);
			svSetValue (ifcfg, "TYPE", NULL, FALSE);
		}
	}

	/* secondary connection UUIDs */
	svSetValue (ifcfg, "SECONDARY_UUIDS", NULL, FALSE);
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
		svSetValue (ifcfg, "SECONDARY_UUIDS", str->str, FALSE);
		g_string_free (str, TRUE);
	}

	svSetValue (ifcfg, "GATEWAY_PING_TIMEOUT", NULL, FALSE);
	if (nm_setting_connection_get_gateway_ping_timeout (s_con)) {
		tmp = g_strdup_printf ("%" G_GUINT32_FORMAT, nm_setting_connection_get_gateway_ping_timeout (s_con));
		svSetValue (ifcfg, "GATEWAY_PING_TIMEOUT", tmp, FALSE);
		g_free (tmp);
	}
}

static gboolean
write_route_file_legacy (const char *filename, NMSettingIPConfig *s_ip4, GError **error)
{
	const char *dest, *next_hop;
	char **route_items;
	char *route_contents;
	NMIPRoute *route;
	guint32 prefix;
	gint64 metric;
	guint32 i, num;
	gboolean success = FALSE;

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
		route = nm_setting_ip_config_get_route (s_ip4, i);

		dest = nm_ip_route_get_dest (route);
		prefix = nm_ip_route_get_prefix (route);
		next_hop = nm_ip_route_get_next_hop (route);
		metric = nm_ip_route_get_metric (route);

		if (metric == -1)
			route_items[i] = g_strdup_printf ("%s/%u via %s\n", dest, prefix, next_hop);
		else
			route_items[i] = g_strdup_printf ("%s/%u via %s metric %u\n", dest, prefix, next_hop, (guint32) metric);
	}
	route_items[num] = NULL;
	route_contents = g_strjoinv (NULL, route_items);
	g_strfreev (route_items);

	if (!g_file_set_contents (filename, route_contents, -1, NULL)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Writing route file '%s' failed", filename);
		goto error;
	}

	success = TRUE;

error:
	g_free (route_contents);

	return success;
}

static gboolean
write_ip4_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingIPConfig *s_ip4;
	const char *value;
	char *addr_key, *prefix_key, *netmask_key, *gw_key, *metric_key, *tmp;
	char *route_path = NULL;
	gint32 j;
	guint32 i, n, num;
	gint64 route_metric;
	GString *searches;
	gboolean success = FALSE;
	gboolean fake_ip4 = FALSE;
	const char *method = NULL;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4)
		method = nm_setting_ip_config_get_method (s_ip4);

	/* Missing IP4 setting is assumed to be DHCP */
	if (!method)
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		int result;

		/* IPv4 disabled, clear IPv4 related parameters */
		svSetValue (ifcfg, "BOOTPROTO", NULL, FALSE);
		for (j = -1; j < 256; j++) {
			if (j == -1) {
				addr_key = g_strdup ("IPADDR");
				prefix_key = g_strdup ("PREFIX");
				netmask_key = g_strdup ("NETMASK");
				gw_key = g_strdup ("GATEWAY");
			} else {
				addr_key = g_strdup_printf ("IPADDR%d", j);
				prefix_key = g_strdup_printf ("PREFIX%d", j);
				netmask_key = g_strdup_printf ("NETMASK%d", j);
				gw_key = g_strdup_printf ("GATEWAY%d", j);
			}

			svSetValue (ifcfg, addr_key, NULL, FALSE);
			svSetValue (ifcfg, prefix_key, NULL, FALSE);
			svSetValue (ifcfg, netmask_key, NULL, FALSE);
			svSetValue (ifcfg, gw_key, NULL, FALSE);

			g_free (addr_key);
			g_free (prefix_key);
			g_free (netmask_key);
			g_free (gw_key);
		}

		route_path = utils_get_route_path (ifcfg->fileName);
		result = unlink (route_path);
		g_free (route_path);
		return TRUE;
	}

	/* Temporarily create fake IP4 setting if missing; method set to DHCP above */
	if (!s_ip4) {
		s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
		fake_ip4 = TRUE;
	}

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO))
		svSetValue (ifcfg, "BOOTPROTO", "dhcp", FALSE);
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
		svSetValue (ifcfg, "BOOTPROTO", "none", FALSE);
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
		svSetValue (ifcfg, "BOOTPROTO", "autoip", FALSE);
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
		svSetValue (ifcfg, "BOOTPROTO", "shared", FALSE);

	/* Clear out un-numbered IP address fields */
	svSetValue (ifcfg, "IPADDR", NULL, FALSE);
	svSetValue (ifcfg, "PREFIX", NULL, FALSE);
	svSetValue (ifcfg, "NETMASK", NULL, FALSE);
	svSetValue (ifcfg, "GATEWAY", NULL, FALSE);
	/* Clear out zero-indexed IP address fields */
	svSetValue (ifcfg, "IPADDR0", NULL, FALSE);
	svSetValue (ifcfg, "PREFIX0", NULL, FALSE);
	svSetValue (ifcfg, "NETMASK0", NULL, FALSE);
	svSetValue (ifcfg, "GATEWAY0", NULL, FALSE);

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
			addr_key = g_strdup ("IPADDR");
			prefix_key = g_strdup ("PREFIX");
			netmask_key = g_strdup ("NETMASK");
			gw_key = g_strdup ("GATEWAY");
		} else {
			addr_key = g_strdup_printf ("IPADDR%d", n);
			prefix_key = g_strdup_printf ("PREFIX%d", n);
			netmask_key = g_strdup_printf ("NETMASK%d", n);
			gw_key = g_strdup_printf ("GATEWAY%d", n);
		}

		svSetValue (ifcfg, addr_key, nm_ip_address_get_address (addr), FALSE);

		tmp = g_strdup_printf ("%u", nm_ip_address_get_prefix (addr));
		svSetValue (ifcfg, prefix_key, tmp, FALSE);
		g_free (tmp);

		svSetValue (ifcfg, netmask_key, NULL, FALSE);
		svSetValue (ifcfg, gw_key, NULL, FALSE);

		g_free (addr_key);
		g_free (prefix_key);
		g_free (netmask_key);
		g_free (gw_key);
		n++;
	}

	/* Clear remaining IPADDR<n..255>, etc */
	for (; n < 256; n++) {
		addr_key = g_strdup_printf ("IPADDR%d", n);
		prefix_key = g_strdup_printf ("PREFIX%d", n);
		netmask_key = g_strdup_printf ("NETMASK%d", n);
		gw_key = g_strdup_printf ("GATEWAY%d", n);

		svSetValue (ifcfg, addr_key, NULL, FALSE);
		svSetValue (ifcfg, prefix_key, NULL, FALSE);
		svSetValue (ifcfg, netmask_key, NULL, FALSE);
		svSetValue (ifcfg, gw_key, NULL, FALSE);

		g_free (addr_key);
		g_free (prefix_key);
		g_free (netmask_key);
		g_free (gw_key);
	}

	svSetValue (ifcfg, "GATEWAY", nm_setting_ip_config_get_gateway (s_ip4), FALSE);

	num = nm_setting_ip_config_get_num_dns (s_ip4);
	for (i = 0; i < 254; i++) {
		const char *dns;

		addr_key = g_strdup_printf ("DNS%d", i + 1);

		if (i >= num)
			svSetValue (ifcfg, addr_key, NULL, FALSE);
		else {
			dns = nm_setting_ip_config_get_dns (s_ip4, i);
			svSetValue (ifcfg, addr_key, dns, FALSE);
		}
		g_free (addr_key);
	}

	num = nm_setting_ip_config_get_num_dns_searches (s_ip4);
	if (num > 0) {
		searches = g_string_new (NULL);
		for (i = 0; i < num; i++) {
			if (i > 0)
				g_string_append_c (searches, ' ');
			g_string_append (searches, nm_setting_ip_config_get_dns_search (s_ip4, i));
		}
		svSetValue (ifcfg, "DOMAIN", searches->str, FALSE);
		g_string_free (searches, TRUE);
	} else
		svSetValue (ifcfg, "DOMAIN", NULL, FALSE);

	/* DEFROUTE; remember that it has the opposite meaning from never-default */
	svSetValue (ifcfg, "DEFROUTE",
	            nm_setting_ip_config_get_never_default (s_ip4) ? "no" : "yes",
	            FALSE);

	svSetValue (ifcfg, "PEERDNS", NULL, FALSE);
	svSetValue (ifcfg, "PEERROUTES", NULL, FALSE);
	svSetValue (ifcfg, "DHCP_CLIENT_ID", NULL, FALSE);
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		svSetValue (ifcfg, "PEERDNS",
		            nm_setting_ip_config_get_ignore_auto_dns (s_ip4) ? "no" : "yes",
		            FALSE);

		svSetValue (ifcfg, "PEERROUTES",
		            nm_setting_ip_config_get_ignore_auto_routes (s_ip4) ? "no" : "yes",
		            FALSE);

		value = nm_setting_ip_config_get_dhcp_hostname (s_ip4);
		if (value)
			svSetValue (ifcfg, "DHCP_HOSTNAME", value, FALSE);

		/* Missing DHCP_SEND_HOSTNAME means TRUE, and we prefer not write it explicitly
		 * in that case, because it is NM-specific variable
		 */
		svSetValue (ifcfg, "DHCP_SEND_HOSTNAME",
		            nm_setting_ip_config_get_dhcp_send_hostname (s_ip4) ? NULL : "no",
		            FALSE);

		value = nm_setting_ip4_config_get_dhcp_client_id (NM_SETTING_IP4_CONFIG (s_ip4));
		if (value)
			svSetValue (ifcfg, "DHCP_CLIENT_ID", value, FALSE);
	}

	svSetValue (ifcfg, "IPV4_FAILURE_FATAL",
	            nm_setting_ip_config_get_may_fail (s_ip4) ? "no" : "yes",
	            FALSE);

	route_metric = nm_setting_ip_config_get_route_metric (s_ip4);
	tmp = route_metric != -1 ? g_strdup_printf ("%"G_GINT64_FORMAT, route_metric) : NULL;
	svSetValue (ifcfg, "IPV4_ROUTE_METRIC", tmp, FALSE);
	g_free (tmp);

	/* Static routes - route-<name> file */
	route_path = utils_get_route_path (ifcfg->fileName);
	if (!route_path) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not get route file path for '%s'", ifcfg->fileName);
		goto out;
	}

	if (utils_has_route_file_new_syntax (route_path)) {
		shvarFile *routefile;

		routefile = utils_get_route_ifcfg (ifcfg->fileName, TRUE);
		if (!routefile) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Could not create route file '%s'", route_path);
			g_free (route_path);
			goto out;
		}
		g_free (route_path);

		num = nm_setting_ip_config_get_num_routes (s_ip4);
		for (i = 0; i < 256; i++) {
			char buf[INET_ADDRSTRLEN];
			NMIPRoute *route;
			guint32 netmask;
			gint64 metric;

			addr_key = g_strdup_printf ("ADDRESS%d", i);
			netmask_key = g_strdup_printf ("NETMASK%d", i);
			gw_key = g_strdup_printf ("GATEWAY%d", i);
			metric_key = g_strdup_printf ("METRIC%d", i);

			if (i >= num) {
				svSetValue (routefile, addr_key, NULL, FALSE);
				svSetValue (routefile, netmask_key, NULL, FALSE);
				svSetValue (routefile, gw_key, NULL, FALSE);
				svSetValue (routefile, metric_key, NULL, FALSE);
			} else {
				route = nm_setting_ip_config_get_route (s_ip4, i);

				svSetValue (routefile, addr_key, nm_ip_route_get_dest (route), FALSE);

				memset (buf, 0, sizeof (buf));
				netmask = nm_utils_ip4_prefix_to_netmask (nm_ip_route_get_prefix (route));
				inet_ntop (AF_INET, (const void *) &netmask, &buf[0], sizeof (buf));
				svSetValue (routefile, netmask_key, &buf[0], FALSE);

				svSetValue (routefile, gw_key, nm_ip_route_get_next_hop (route), FALSE);

				memset (buf, 0, sizeof (buf));
				metric = nm_ip_route_get_metric (route);
				if (metric == -1)
					svSetValue (routefile, metric_key, NULL, FALSE);
				else {
					tmp = g_strdup_printf ("%u", (guint32) metric);
					svSetValue (routefile, metric_key, tmp, FALSE);
					g_free (tmp);
				}
			}

			g_free (addr_key);
			g_free (netmask_key);
			g_free (gw_key);
			g_free (metric_key);
		}
		if (!svWriteFile (routefile, 0644, error)) {
			svCloseFile (routefile);
			goto out;
		}
		svCloseFile (routefile);
	} else {
		write_route_file_legacy (route_path, s_ip4, error);
		g_free (route_path);
		if (error && *error)
			goto out;
	}

	success = TRUE;

out:
	if (fake_ip4)
		g_object_unref (s_ip4);

	return success;
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

	if (utils_ignore_ip_config (connection))
		return;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4)
		return;

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

		svSetValue (ifcfg, "DEVICE", label, FALSE);

		addr = nm_setting_ip_config_get_address (s_ip4, i);
		svSetValue (ifcfg, "IPADDR", nm_ip_address_get_address (addr), FALSE);

		tmp = g_strdup_printf ("%u", nm_ip_address_get_prefix (addr));
		svSetValue (ifcfg, "PREFIX", tmp, FALSE);
		g_free (tmp);

		svWriteFile (ifcfg, 0644, NULL);
		svCloseFile (ifcfg);
	}
}

static gboolean
write_route6_file (const char *filename, NMSettingIPConfig *s_ip6, GError **error)
{
	char **route_items;
	char *route_contents;
	NMIPRoute *route;
	guint32 i, num;
	gboolean success = FALSE;

	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (s_ip6 != NULL, FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	num = nm_setting_ip_config_get_num_routes (s_ip6);
	if (num == 0) {
		unlink (filename);
		return TRUE;
	}

	route_items = g_malloc0 (sizeof (char*) * (num + 1));
	for (i = 0; i < num; i++) {
		route = nm_setting_ip_config_get_route (s_ip6, i);

		if (nm_ip_route_get_metric (route) == -1) {
			route_items[i] = g_strdup_printf ("%s/%u via %s\n",
			                                  nm_ip_route_get_dest (route),
			                                  nm_ip_route_get_prefix (route),
			                                  nm_ip_route_get_next_hop (route));
		} else {
			route_items[i] = g_strdup_printf ("%s/%u via %s metric %u\n",
			                                  nm_ip_route_get_dest (route),
			                                  nm_ip_route_get_prefix (route),
			                                  nm_ip_route_get_next_hop (route),
			                                  (guint32) nm_ip_route_get_metric (route));
		}
	}
	route_items[num] = NULL;
	route_contents = g_strjoinv (NULL, route_items);
	g_strfreev (route_items);

	if (!g_file_set_contents (filename, route_contents, -1, NULL)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Writing route6 file '%s' failed", filename);
		goto error;
	}

	success = TRUE;

error:
	g_free (route_contents);
	return success;
}

static gboolean
write_ip6_setting (NMConnection *connection, shvarFile *ifcfg, GError **error)
{
	NMSettingIPConfig *s_ip6;
	NMSettingIPConfig *s_ip4;
	const char *value;
	char *addr_key;
	char *tmp;
	guint32 i, num, num4;
	GString *searches;
	NMIPAddress *addr;
	const char *dns;
	gint64 route_metric;
	GString *ip_str1, *ip_str2, *ip_ptr;
	char *route6_path;

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip6) {
		/* Treat missing IPv6 setting as a setting with method "auto" */
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_AUTOCONF", "yes", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
		svSetValue (ifcfg, "IPV6_DEFROUTE", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_PEERDNS", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_PEERROUTES", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_FAILURE_FATAL", "no", FALSE);
		svSetValue (ifcfg, "IPV6_ROUTE_METRIC", NULL, FALSE);
		return TRUE;
	}

	value = nm_setting_ip_config_get_method (s_ip6);
	g_assert (value);
	if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
		svSetValue (ifcfg, "IPV6INIT", "no", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
		return TRUE;
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_AUTOCONF", "yes", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
		const char *hostname;
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_AUTOCONF", "no", FALSE);
		svSetValue (ifcfg, "DHCPV6C", "yes", FALSE);
		hostname = nm_setting_ip_config_get_dhcp_hostname (s_ip6);
		if (hostname)
			svSetValue (ifcfg, "DHCP_HOSTNAME", hostname, FALSE);
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_AUTOCONF", "no", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)) {
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "IPV6_AUTOCONF", "no", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		svSetValue (ifcfg, "IPV6INIT", "yes", FALSE);
		svSetValue (ifcfg, "DHCPV6C", NULL, FALSE);
		/* TODO */
	}

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
	svSetValue (ifcfg, "IPV6ADDR", ip_str1->str, FALSE);
	svSetValue (ifcfg, "IPV6ADDR_SECONDARIES", ip_str2->str, FALSE);
	svSetValue (ifcfg, "IPV6_DEFAULTGW", nm_setting_ip_config_get_gateway (s_ip6), FALSE);
	g_string_free (ip_str1, TRUE);
	g_string_free (ip_str2, TRUE);

	/* Write out DNS - 'DNS' key is used both for IPv4 and IPv6 */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	num4 = s_ip4 ? nm_setting_ip_config_get_num_dns (s_ip4) : 0; /* from where to start with IPv6 entries */
	num = nm_setting_ip_config_get_num_dns (s_ip6);
	for (i = 0; i < 254; i++) {
		addr_key = g_strdup_printf ("DNS%d", i + num4 + 1);

		if (i >= num)
			svSetValue (ifcfg, addr_key, NULL, FALSE);
		else {
			dns = nm_setting_ip_config_get_dns (s_ip6, i);
			svSetValue (ifcfg, addr_key, dns, FALSE);
		}
		g_free (addr_key);
	}

	/* Write out DNS domains - 'DOMAIN' key is shared for both IPv4 and IPv6 domains */
	num = nm_setting_ip_config_get_num_dns_searches (s_ip6);
	if (num > 0) {
		char *ip4_domains;
		ip4_domains = svGetValue (ifcfg, "DOMAIN", FALSE);
		searches = g_string_new (ip4_domains);
		for (i = 0; i < num; i++) {
			if (searches->len > 0)
				g_string_append_c (searches, ' ');
			g_string_append (searches, nm_setting_ip_config_get_dns_search (s_ip6, i));
		}
		svSetValue (ifcfg, "DOMAIN", searches->str, FALSE);
		g_string_free (searches, TRUE);
		g_free (ip4_domains);
	}

	/* handle IPV6_DEFROUTE */
	/* IPV6_DEFROUTE has the opposite meaning from 'never-default' */
	if (nm_setting_ip_config_get_never_default(s_ip6))
		svSetValue (ifcfg, "IPV6_DEFROUTE", "no", FALSE);
	else
		svSetValue (ifcfg, "IPV6_DEFROUTE", "yes", FALSE);

	svSetValue (ifcfg, "IPV6_PEERDNS", NULL, FALSE);
	svSetValue (ifcfg, "IPV6_PEERROUTES", NULL, FALSE);
	if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
		svSetValue (ifcfg, "IPV6_PEERDNS",
		            nm_setting_ip_config_get_ignore_auto_dns (s_ip6) ? "no" : "yes",
		            FALSE);

		svSetValue (ifcfg, "IPV6_PEERROUTES",
		            nm_setting_ip_config_get_ignore_auto_routes (s_ip6) ? "no" : "yes",
		            FALSE);
	}

	svSetValue (ifcfg, "IPV6_FAILURE_FATAL",
	            nm_setting_ip_config_get_may_fail (s_ip6) ? "no" : "yes",
	            FALSE);

	route_metric = nm_setting_ip_config_get_route_metric (s_ip6);
	tmp = route_metric != -1 ? g_strdup_printf ("%"G_GINT64_FORMAT, route_metric) : NULL;
	svSetValue (ifcfg, "IPV6_ROUTE_METRIC", tmp, FALSE);
	g_free (tmp);

	/* IPv6 Privacy Extensions */
	svSetValue (ifcfg, "IPV6_PRIVACY", NULL, FALSE);
	svSetValue (ifcfg, "IPV6_PRIVACY_PREFER_PUBLIC_IP", NULL, FALSE);
	switch (nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (s_ip6))){
	case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
		svSetValue (ifcfg, "IPV6_PRIVACY", "no", FALSE);
	break;
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
		svSetValue (ifcfg, "IPV6_PRIVACY", "rfc3041", FALSE);
		svSetValue (ifcfg, "IPV6_PRIVACY_PREFER_PUBLIC_IP", "yes", FALSE);
	break;
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
		svSetValue (ifcfg, "IPV6_PRIVACY", "rfc3041", FALSE);
	break;
	default:
	break;
	}

	/* Static routes go to route6-<dev> file */
	route6_path = utils_get_route6_path (ifcfg->fileName);
	if (!route6_path) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not get route6 file path for '%s'", ifcfg->fileName);
		goto error;
	}
	write_route6_file (route6_path, s_ip6, error);
	g_free (route6_path);
	if (error && *error)
		goto error;

	return TRUE;

error:
	return FALSE;
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
	GPtrArray *array;
	GString *value;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	array = g_ptr_array_new ();

	if (s_ip4) {
		method = nm_setting_ip_config_get_method (s_ip4);
		if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
			num_options = nm_setting_ip_config_get_num_dns_options (s_ip4);
			for (i = 0; i < num_options; i++)
				add_dns_option (array, nm_setting_ip_config_get_dns_option (s_ip4, i));
		}
	}

	if (s_ip6) {
		method = nm_setting_ip_config_get_method (s_ip6);
		if (g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
			num_options = nm_setting_ip_config_get_num_dns_options (s_ip6);
			for (i = 0; i < num_options; i++)
				add_dns_option (array, nm_setting_ip_config_get_dns_option (s_ip6, i));
		}
	}

	if (array->len > 0) {
		value = g_string_new (NULL);
		for (i = 0; i < array->len; i++) {
			if (i > 0)
				g_string_append_c (value, ' ');
			g_string_append (value, array->pdata[i]);
		}
		svSetValue (ifcfg, "RES_OPTIONS", value->str, FALSE);
		g_string_free (value, TRUE);
	} else
		svSetValue (ifcfg, "RES_OPTIONS", NULL, FALSE);

	g_ptr_array_unref (array);
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
                  const char *keyfile,
                  char **out_filename,
                  GError **error)
{
	NMSettingConnection *s_con;
	gboolean success = FALSE;
	shvarFile *ifcfg = NULL;
	char *ifcfg_name = NULL;
	const char *type;
	gboolean no_8021x = FALSE;
	gboolean wired = FALSE;

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

			g_free (ifcfg_name);
			while (idx++ < 500) {
				ifcfg_name = g_strdup_printf ("%s/ifcfg-%s-%u", ifcfg_dir, escaped, idx);
				if (g_file_test (ifcfg_name, G_FILE_TEST_EXISTS) == FALSE)
					break;
				g_free (ifcfg_name);
				ifcfg_name = NULL;
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
		goto out;
	}

	if (!strcmp (type, NM_SETTING_WIRED_SETTING_NAME)) {
		// FIXME: can't write PPPoE at this time
		if (nm_connection_get_setting_pppoe (connection)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Can't write connection type '%s'",
			             NM_SETTING_PPPOE_SETTING_NAME);
			goto out;
		}

		if (!write_wired_setting (connection, ifcfg, error))
			goto out;
		wired = TRUE;
	} else if (!strcmp (type, NM_SETTING_VLAN_SETTING_NAME)) {
		if (!write_vlan_setting (connection, ifcfg, &wired, error))
			goto out;
	} else if (!strcmp (type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		if (!write_wireless_setting (connection, ifcfg, &no_8021x, error))
			goto out;
	} else if (!strcmp (type, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		if (!write_infiniband_setting (connection, ifcfg, error))
			goto out;
	} else if (!strcmp (type, NM_SETTING_BOND_SETTING_NAME)) {
		if (!write_bonding_setting (connection, ifcfg, error))
			goto out;
	} else if (!strcmp (type, NM_SETTING_TEAM_SETTING_NAME)) {
		if (!write_team_setting (connection, ifcfg, error))
			goto out;
	} else if (!strcmp (type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		if (!write_bridge_setting (connection, ifcfg, error))
			goto out;
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Can't write connection type '%s'", type);
		goto out;
	}

	if (!no_8021x) {
		if (!write_8021x_setting (connection, ifcfg, wired, error))
			goto out;
	}

	if (!write_bridge_port_setting (connection, ifcfg, error))
		goto out;

	if (!write_team_port_setting (connection, ifcfg, error))
		goto out;

	if (!write_dcb_setting (connection, ifcfg, error))
		goto out;

	if (!utils_ignore_ip_config (connection)) {
		svSetValue (ifcfg, "DHCP_HOSTNAME", NULL, FALSE);

		if (!write_ip4_setting (connection, ifcfg, error))
			goto out;
		write_ip4_aliases (connection, ifcfg_name);

		if (!write_ip6_setting (connection, ifcfg, error))
			goto out;

		if (!write_res_options (connection, ifcfg, error))
			goto out;
	}

	write_connection_setting (s_con, ifcfg);

	if (!svWriteFile (ifcfg, 0644, error))
		goto out;

	/* Only return the filename if this was a newly written ifcfg */
	if (out_filename && !filename)
		*out_filename = g_strdup (ifcfg_name);

	success = TRUE;

out:
	if (ifcfg)
		svCloseFile (ifcfg);
	g_free (ifcfg_name);
	return success;
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
                       GError **error)
{
	return write_connection (connection, ifcfg_dir, NULL, NULL, out_filename, error);
}

gboolean
writer_update_connection (NMConnection *connection,
                          const char *ifcfg_dir,
                          const char *filename,
                          const char *keyfile,
                          GError **error)
{
	if (utils_has_complex_routes (filename)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Cannot modify a connection that has an associated 'rule-' or 'rule6-' file");
		return FALSE;
	}

	return write_connection (connection, ifcfg_dir, filename, keyfile, NULL, error);
}

