/*
 *
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
 * Copyright 2015 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include "nm-keyfile-utils.h"
#include "nm-keyfile-internal.h"
#include "nm-simple-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-8021x.h"
#include "nm-setting-team.h"
#include "nm-setting-user.h"
#include "nm-setting-proxy.h"

#include "nm-utils/nm-test-utils.h"

#define TEST_CERT_DIR              NM_BUILD_SRCDIR"/libnm-core/tests/certs"
#define TEST_WIRED_TLS_CA_CERT     TEST_CERT_DIR"/test-ca-cert.pem"
#define TEST_WIRED_TLS_PRIVKEY     TEST_CERT_DIR"/test-key-and-cert.pem"
#define TEST_WIRED_TLS_TPM2KEY     TEST_CERT_DIR"/test-tpm2wrapped-key.pem"

/*****************************************************************************/

static void
do_test_encode_key_full (GKeyFile *kf, const char *name, const char *key, const char *key_decode_encode)
{
	gs_free char *to_free1 = NULL;
	gs_free char *to_free2 = NULL;
	const char *key2;
	const char *name2;

	g_assert (key);

	if (name) {
		key2 = nm_keyfile_key_encode (name, &to_free1);
		g_assert (key2);
		g_assert (NM_STRCHAR_ALL (key2, ch, (guchar) ch < 127));
		g_assert_cmpstr (key2, ==, key);

		/* try to add the encoded key to the keyfile. We expect
		 * no g_critical warning about invalid key. */
		g_key_file_set_value (kf, "group", key, "dummy");
	}

	name2 = nm_keyfile_key_decode (key, &to_free2);
	if (name)
		g_assert_cmpstr (name2, ==, name);
	else {
		key2 = nm_keyfile_key_encode (name2, &to_free1);
		g_assert (key2);
		g_assert (NM_STRCHAR_ALL (key2, ch, (guchar) ch < 127));
		if (key_decode_encode)
			g_assert_cmpstr (key2, ==, key_decode_encode);
		g_key_file_set_value (kf, "group", key2, "dummy");
	}
}

#define do_test_encode_key_bijection(kf, name, key)                      do_test_encode_key_full (kf, ""name, ""key,  NULL)
#define do_test_encode_key_identity(kf, name)                            do_test_encode_key_full (kf, ""name, ""name, NULL)
#define do_test_encode_key_decode_surjection(kf, key, key_decode_encode) do_test_encode_key_full (kf, NULL,   ""key,  ""key_decode_encode)

static void
test_encode_key (void)
{
	gs_unref_keyfile GKeyFile *kf = g_key_file_new ();

	do_test_encode_key_identity (kf, "a");
	do_test_encode_key_bijection (kf, "", "\\00");
	do_test_encode_key_bijection (kf, " ", "\\20");
	do_test_encode_key_bijection (kf, "\\ ", "\\\\20");
	do_test_encode_key_identity (kf, "\\0");
	do_test_encode_key_identity (kf, "\\a");
	do_test_encode_key_identity (kf, "\\0g");
	do_test_encode_key_bijection (kf, "\\0f", "\\5C0f");
	do_test_encode_key_bijection (kf, "\\0f ", "\\5C0f\\20");
	do_test_encode_key_bijection (kf, " \\0f ", "\\20\\5C0f\\20");
	do_test_encode_key_bijection (kf, "\xF5", "\\F5");
	do_test_encode_key_bijection (kf, "\x7F", "\\7F");
	do_test_encode_key_bijection (kf, "\x1f", "\\1F");
	do_test_encode_key_bijection (kf, "  ", "\\20\\20");
	do_test_encode_key_bijection (kf, "   ", "\\20 \\20");
	do_test_encode_key_decode_surjection (kf, "f\\20c", "f c");
	do_test_encode_key_decode_surjection (kf, "\\20\\20\\20", "\\20 \\20");

	do_test_encode_key_bijection (kf, "\t", "\\09");
	do_test_encode_key_bijection (kf, "\t=x", "\\09\\3Dx");
	do_test_encode_key_bijection (kf, "(nm-openvpn-auth-dialog:10283): GdkPixbuf-DEBUG: \tCopy pixels == false",
	                                  "(nm-openvpn-auth-dialog:10283): GdkPixbuf-DEBUG: \\09Copy pixels \\3D\\3D false");
}

/*****************************************************************************/

#define CLEAR(con, keyfile) \
	G_STMT_START { \
		NMConnection **_con = (con); \
		GKeyFile **_keyfile = (keyfile); \
		\
		g_clear_object (_con); \
		g_clear_pointer (_keyfile, g_key_file_unref); \
	} G_STMT_END

static void
_assert_gbytes (GBytes *bytes, gconstpointer data, gssize len)
{
	g_assert ((data && len > 0) || !len || (data && len == -1));

	if (len == -1)
		len = strlen (data);

	if (!len)
		g_assert (!bytes);

	g_assert (nm_utils_gbytes_equal_mem (bytes, data, len));
}

static GKeyFile *
_keyfile_load_from_data (const char *str)
{
	GError *error = NULL;
	gboolean success;
	GKeyFile *keyfile;

	g_assert (str);

	keyfile =  g_key_file_new ();
	success = g_key_file_load_from_data (keyfile, str, strlen (str), G_KEY_FILE_NONE, &error);
	g_assert_no_error (error);
	g_assert (success);

	return keyfile;
}

static GKeyFile *
_nm_keyfile_write (NMConnection *connection,
                   NMKeyfileWriteHandler handler,
                   void *user_data)
{
	GError *error = NULL;
	GKeyFile *kf;

	g_assert (NM_IS_CONNECTION (connection));

	kf = nm_keyfile_write (connection, handler, user_data, &error);
	g_assert_no_error (error);
	g_assert (kf);
	return kf;
}

static NMConnection *
_nm_keyfile_read (GKeyFile *keyfile,
                  const char *keyfile_name,
                  NMKeyfileReadHandler read_handler,
                  void *read_data,
                  gboolean needs_normalization)
{
	GError *error = NULL;
	NMConnection *con;
	gs_free char *filename = NULL;
	gs_free char *base_dir = NULL;

	g_assert (keyfile);
	g_assert (!keyfile_name || (keyfile_name[0] == '/'));

	base_dir = g_path_get_dirname (keyfile_name);
	filename = g_path_get_basename (keyfile_name);

	con = nm_keyfile_read (keyfile, base_dir, read_handler, read_data, &error);
	g_assert_no_error (error);
	g_assert (NM_IS_CONNECTION (con));

	nm_keyfile_read_ensure_id (con, filename);
	nm_keyfile_read_ensure_uuid (con, keyfile_name);

	if (needs_normalization) {
		nmtst_assert_connection_verifies_after_normalization (con, 0, 0);
		nmtst_connection_normalize (con);
	} else {
		{
			NMSettingConnection *s_con;

			/* a non-slave connection must have a proxy setting, but
			 * keyfile reader does not add that (unless a [proxy] section
			 * is present. */
			s_con = nm_connection_get_setting_connection (con);
			if (   s_con
			    && !nm_setting_connection_get_master (s_con)
			    && !nm_connection_get_setting_proxy (con))
				nm_connection_add_setting (con, nm_setting_proxy_new ());
		}
		nmtst_assert_connection_verifies_without_normalization (con);
	}
	return con;
}

static void
_keyfile_convert (NMConnection **con,
                  GKeyFile **keyfile,
                  const char *keyfile_name,
                  NMKeyfileReadHandler read_handler,
                  void *read_data,
                  NMKeyfileWriteHandler write_handler,
                  void *write_data,
                  gboolean needs_normalization)
{
	NMConnection *c0;
	GKeyFile *k0;
	gs_unref_object NMConnection *c0_k1_c2 = NULL, *k0_c1 = NULL, *k0_c1_k2_c3 = NULL;
	gs_unref_keyfile GKeyFile *k0_c1_k2 = NULL, *c0_k1 = NULL, *c0_k1_c2_k3 = NULL;

	/* convert from @con to @keyfile and check that we can make
	 * full round trips and obtaining the same result. */

	g_assert (con);
	g_assert (keyfile);
	g_assert (*con || *keyfile);

	c0 = *con;
	k0 = *keyfile;

	if (c0) {
		c0_k1 = _nm_keyfile_write (c0, write_handler, write_data);
		c0_k1_c2 = _nm_keyfile_read (c0_k1, keyfile_name, read_handler, read_data, FALSE);
		c0_k1_c2_k3 = _nm_keyfile_write (c0_k1_c2, write_handler, write_data);

		g_assert (_nm_keyfile_equals (c0_k1, c0_k1_c2_k3, TRUE));
	}
	if (k0) {
		NMSetting8021x *s1, *s2;

		k0_c1 = _nm_keyfile_read (k0, keyfile_name, read_handler, read_data, needs_normalization);
		k0_c1_k2 = _nm_keyfile_write (k0_c1, write_handler, write_data);
		k0_c1_k2_c3 = _nm_keyfile_read (k0_c1_k2, keyfile_name, read_handler, read_data, FALSE);

		/* It is a expected behavior, that if @k0 contains a relative path ca-cert, @k0_c1 will
		 * contain that path as relative. But @k0_c1_k2 and @k0_c1_k2_c3 will have absolute paths.
		 * In this case, hack up @k0_c1_k2_c3 to contain the same relative path. */
		s1 = nm_connection_get_setting_802_1x (k0_c1);
		s2 = nm_connection_get_setting_802_1x (k0_c1_k2_c3);
		if (s1 || s2) {
			g_assert_cmpint (nm_setting_802_1x_get_ca_cert_scheme (s1), ==, nm_setting_802_1x_get_ca_cert_scheme (s2));
			switch (nm_setting_802_1x_get_ca_cert_scheme (s1)) {
			case NM_SETTING_802_1X_CK_SCHEME_PATH:
				{
					const char *p1 = nm_setting_802_1x_get_ca_cert_path (s1);
					const char *p2 = nm_setting_802_1x_get_ca_cert_path (s2);

					nmtst_assert_resolve_relative_path_equals (p1, p2);
					if (strcmp (p1, p2) != 0) {
						gs_free char *puri = NULL;
						gs_unref_bytes GBytes *pfile = NULL;

						g_assert (p1[0] != '/' && p2[0] == '/');

						/* one of the paths is a relative path and the other is absolute. This is an
						 * expected difference.
						 * Make the paths of s2 identical to s1... */
						puri = g_strconcat (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, p1, NULL);
						pfile = g_bytes_new (puri, strlen (puri) + 1);
						g_object_set (s2, NM_SETTING_802_1X_CA_CERT, pfile, NULL);
					}
				}
				break;
			case NM_SETTING_802_1X_CK_SCHEME_BLOB: {
				GBytes *b1, *b2;

				b1 = nm_setting_802_1x_get_ca_cert_blob (s1);
				b2 = nm_setting_802_1x_get_ca_cert_blob (s2);
				g_assert (b1);
				g_assert (b2);
				g_assert (g_bytes_equal (b1, b2));
				break;
			}
			default:
				break;
			}
		}

		nmtst_assert_connection_equals (k0_c1, FALSE, k0_c1_k2_c3, FALSE);
	}

	if (!k0)
		*keyfile = g_key_file_ref (c0_k1);
	else if (!c0)
		*con = g_object_ref (k0_c1);
	else {
		/* finally, if both a keyfile and a connection are given, assert that they are equal
		 * after a round of conversion. */
		g_assert (_nm_keyfile_equals (c0_k1, k0_c1_k2, TRUE));
		nmtst_assert_connection_equals (k0_c1, FALSE, c0_k1_c2, FALSE);
	}
}

/*****************************************************************************/

static void
_test_8021x_cert_check (NMConnection *con,
                        NMSetting8021xCKScheme expected_scheme,
                        const void *value,
                        gssize val_len)
{
	GKeyFile *keyfile = NULL;
	NMSetting8021x *s_8021x;
	gs_free char *kval = NULL;

	_keyfile_convert (&con, &keyfile, "/_test_8021x_cert_check/foo", NULL, NULL, NULL, NULL, FALSE);

	s_8021x = nm_connection_get_setting_802_1x (con);

	g_assert (nm_setting_802_1x_get_ca_cert_scheme (s_8021x) == expected_scheme);

	if (expected_scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		const char *path = nm_setting_802_1x_get_ca_cert_path (s_8021x);

		g_assert_cmpstr (path, ==, value);
		g_assert (val_len == -1 || strlen (path) == val_len);

		kval = g_key_file_get_string (keyfile, "802-1x", "ca-cert", NULL);
		g_assert (kval);
		g_assert_cmpstr (kval, ==, value);
	} else if (expected_scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		GBytes *blob = nm_setting_802_1x_get_ca_cert_blob (s_8021x);
		gs_free char *file_blob = NULL;

		if (val_len == -1) {
			gsize l;
			gboolean success;

			success = g_file_get_contents (value, &file_blob, &l, NULL);
			g_assert (success);

			value = file_blob;
			val_len = l;
		}

		g_assert (blob);
		g_assert (nm_utils_gbytes_equal_mem (blob, value, val_len));

		kval = g_key_file_get_string (keyfile, "802-1x", "ca-cert", NULL);
		g_assert (kval);
		g_assert (g_str_has_prefix (kval, NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB));
	}

	g_key_file_unref (keyfile);
}

static void
_test_8021x_cert_check_blob_full (NMConnection *con, const void *data, gsize len)
{
	GBytes *bytes;
	NMSetting8021x *s_8021x = nm_connection_get_setting_802_1x (con);

	bytes = g_bytes_new (data, len);
	g_object_set (s_8021x,
	              NM_SETTING_802_1X_CA_CERT,
                  bytes,
                  NULL);
	_test_8021x_cert_check (con, NM_SETTING_802_1X_CK_SCHEME_BLOB, g_bytes_get_data (bytes, NULL), g_bytes_get_size (bytes));
	g_bytes_unref (bytes);
}
#define _test_8021x_cert_check_blob(con, data) _test_8021x_cert_check_blob_full(con, data, NM_STRLEN (data))

static void
_test_8021x_cert_from_files (const char *cert, const char *key)
{
	NMSetting8021x *s_8021x;
	gs_unref_object NMConnection *con = nmtst_create_minimal_connection ("test-cert", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	GError *error = NULL;
	gboolean success;
	NMSetting8021xCKScheme scheme = NM_SETTING_802_1X_CK_SCHEME_PATH;
	gs_free char *full_TEST_WIRED_TLS_CA_CERT = nmtst_file_resolve_relative_path (cert, NULL);
	gs_free char *full_TEST_WIRED_TLS_PRIVKEY = nmtst_file_resolve_relative_path (key, NULL);

	/* test writing/reading of certificates of NMSetting8021x */

	/* create a valid connection with NMSetting8021x */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_setting_802_1x_add_eap_method (s_8021x, "tls");
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, "Bill Smith", NULL);
	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         full_TEST_WIRED_TLS_CA_CERT,
	                                         scheme,
	                                         NULL,
	                                         &error);
	g_assert_no_error (error);
	g_assert (success);
	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             full_TEST_WIRED_TLS_CA_CERT,
	                                             scheme,
	                                             NULL,
	                                             &error);
	g_assert_no_error (error);
	g_assert (success);
	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             full_TEST_WIRED_TLS_PRIVKEY,
	                                             "test1",
	                                             scheme,
	                                             NULL,
	                                             &error);
	g_assert_no_error (error);
	g_assert (success);

	/* test resetting ca-cert to different values and see whether we can write/read. */

	nm_connection_add_setting (con, NM_SETTING (s_8021x));
	nmtst_assert_connection_verifies_and_normalizable (con);
	nmtst_connection_normalize (con);

	_test_8021x_cert_check (con, scheme, full_TEST_WIRED_TLS_CA_CERT, -1);

	scheme = NM_SETTING_802_1X_CK_SCHEME_BLOB;
	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         full_TEST_WIRED_TLS_CA_CERT,
	                                         scheme,
	                                         NULL,
	                                         &error);
	g_assert_no_error (error);
	g_assert (success);
	_test_8021x_cert_check (con, scheme, full_TEST_WIRED_TLS_CA_CERT, -1);

	_test_8021x_cert_check_blob (con, "a");
	_test_8021x_cert_check_blob (con, "\0");
	_test_8021x_cert_check_blob (con, "10");
	_test_8021x_cert_check_blob (con, "data:;base64,a");
	_test_8021x_cert_check_blob_full (con, "data:;base64,a", NM_STRLEN ("data:;base64,a") + 1);
	_test_8021x_cert_check_blob (con, "data:;base64,file://a");
	_test_8021x_cert_check_blob (con, "123");

}

static void
test_8021x_cert (void)
{
	_test_8021x_cert_from_files (TEST_WIRED_TLS_CA_CERT, TEST_WIRED_TLS_PRIVKEY);
}

static void
test_8021x_cert_tpm2key (void)
{
	_test_8021x_cert_from_files (TEST_WIRED_TLS_CA_CERT, TEST_WIRED_TLS_TPM2KEY);
}

/*****************************************************************************/

static void
test_8021x_cert_read (void)
{
	GKeyFile *keyfile = NULL;
	gs_unref_object NMConnection *con = NULL;
	NMSetting8021x *s_8021x;

	con = nmtst_create_connection_from_keyfile (
	      "[connection]\n"
	      "type=ethernet",
	      "/test_8021x_cert_read/test0");
	CLEAR (&con, &keyfile);

	keyfile = _keyfile_load_from_data (
	          "[connection]\n"
	          "type=ethernet"
	          );
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test1", NULL, NULL, NULL, NULL, TRUE);
	CLEAR (&con, &keyfile);

	keyfile = _keyfile_load_from_data (
	          "[connection]\n"
	          "type=802-3-ethernet\n"

	          "[802-1x]\n"
	          "eap=tls;\n"
	          "identity=Bill Smith\n"
	          "ca-cert=48;130;2;52;48;130;1;161;2;16;2;173;102;126;78;69;254;94;87;111;60;152;25;94;221;192;48;13;6;9;42;134;72;134;247;13;1;1;2;5;0;48;95;49;11;48;9;6;3;85;4;6;19;2;85;83;49;32;48;30;6;3;85;4;10;19;23;82;83;65;32;68;97;116;97;32;83;101;99;117;114;105;116;121;44;32;73;110;99;46;49;46;48;44;6;3;85;4;11;19;37;83;101;99;117;114;101;32;83;101;114;118;101;114;32;67;101;114;116;105;102;105;99;97;116;105;111;110;32;65;117;116;104;111;114;105;116;121;48;30;23;13;57;52;49;49;48;57;48;48;48;48;48;48;90;23;13;49;48;48;49;48;55;50;51;53;57;53;57;90;48;95;49;11;48;9;6;3;85;4;6;19;2;85;83;49;32;48;30;6;3;85;4;10;19;23;82;83;65;32;68;97;116;97;32;83;101;99;117;114;105;116;121;44;32;73;110;99;46;49;46;48;44;6;3;85;4;11;19;37;83;101;99;117;114;101;32;83;101;114;118;101;114;32;67;101;114;116;105;102;105;99;97;116;105;111;110;32;65;117;116;104;111;114;105;116;121;48;129;155;48;13;6;9;42;134;72;134;247;13;1;1;1;5;0;3;129;137;0;48;129;133;2;126;0;146;206;122;193;174;131;62;90;170;137;131;87;172;37;1;118;12;173;174;142;44;55;206;235;53;120;100;84;3;229;132;64;81;201;191;143;8;226;138;130;8;210;22;134;55;85;233;177;33;2;173;118;104;129;154;5;162;75;201;75;37;102;34;86;108;136;7;143;247;129;89;109;132;7;101;112;19;113;118;62;155;119;76;227;80;137;86;152;72;185;29;167;41;26;19;46;74;17;89;156;30;21;213;73;84;44;115;58;105;130;177;151;57;156;109;112;103;72;229;221;45;214;200;30;123;2;3;1;0;1;48;13;6;9;42;134;72;134;247;13;1;1;2;5;0;3;126;0;101;221;126;225;178;236;176;226;58;224;236;113;70;154;25;17;184;211;199;160;180;3;64;38;2;62;9;156;225;18;179;209;90;246;55;165;183;97;3;182;91;22;105;59;198;68;8;12;136;83;12;107;151;73;199;62;53;220;108;185;187;170;223;92;187;58;47;147;96;182;169;75;77;242;32;247;205;95;127;100;123;142;220;0;92;215;250;119;202;57;22;89;111;14;234;211;181;131;127;77;77;66;86;118;180;201;95;4;248;56;248;235;210;95;117;95;205;123;252;229;142;128;124;252;80;\n"
	          "client-cert=102;105;108;101;58;47;47;47;104;111;109;101;47;100;99;98;119;47;68;101;115;107;116;111;112;47;99;101;114;116;105;110;102;114;97;47;99;108;105;101;110;116;46;112;101;109;0;\n"
	          "private-key=102;105;108;101;58;47;47;47;104;111;109;101;47;100;99;98;119;47;68;101;115;107;116;111;112;47;99;101;114;116;105;110;102;114;97;47;99;108;105;101;110;116;46;112;101;109;0;\n"
	          "private-key-password=12345testing\n"
	          );
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, TRUE);
	CLEAR (&con, &keyfile);

	keyfile = _keyfile_load_from_data (
	          "[connection]\n"
	          "type=802-3-ethernet\n"

	          "[802-1x]\n"
	          "eap=tls;\n"
	          "identity=Bill Smith\n"
	          /* unqualified strings are only recognized as path up to 500 chars*/
	          "ca-cert="  "/111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	                      "/111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	                      "/111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	                      "/111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	                      "/11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\n"
	          "client-cert=/222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222221"
	                      "/222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222221"
	                      "/222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222221"
	                      "/222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222221"
	                      "/222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222\n"
	          "private-key=file://"
	                      "/333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333331"
	                      "/333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333331"
	                      "/333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333331"
	                      "/333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333331"
	                      "/33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333111111\n"
	          "private-key-password=12345testing\n"
	          );
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, TRUE);
	s_8021x = nm_connection_get_setting_802_1x (con);

	g_assert (nm_setting_802_1x_get_ca_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert (g_str_has_prefix (nm_setting_802_1x_get_ca_cert_path (s_8021x), "/111111111111"));
	g_assert_cmpint (strlen (nm_setting_802_1x_get_ca_cert_path (s_8021x)), ==, 499);

	g_assert (nm_setting_802_1x_get_client_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB);
	g_assert (g_str_has_prefix (g_bytes_get_data (nm_setting_802_1x_get_client_cert_blob (s_8021x), NULL), "/2222222222"));
	g_assert_cmpint (g_bytes_get_size (nm_setting_802_1x_get_client_cert_blob (s_8021x)), ==, 500 + 1 /* keyfile reader adds a trailing NUL */);

	g_assert (nm_setting_802_1x_get_private_key_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert (g_str_has_prefix (nm_setting_802_1x_get_private_key_path (s_8021x), "/333333333"));
	g_assert_cmpint (strlen (nm_setting_802_1x_get_private_key_path (s_8021x)), ==, 505);
	CLEAR (&con, &keyfile);

	keyfile = _keyfile_load_from_data (
	          "[connection]\n"
	          "type=802-3-ethernet\n"

	          "[802-1x]\n"
	          "eap=tls;\n"
	          "identity=Bill Smith\n"
	          "ca-cert=/\n"
	          "client-cert=a.pem\n"
	          "private-key=data:;base64,aGFsbG8=\n" // hallo
	          "private-key-password=12345testing\n"
	          );
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, TRUE);
	s_8021x = nm_connection_get_setting_802_1x (con);

	g_assert (nm_setting_802_1x_get_ca_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert_cmpstr (nm_setting_802_1x_get_ca_cert_path (s_8021x), ==, "/");

	g_assert (nm_setting_802_1x_get_client_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert_cmpstr (nm_setting_802_1x_get_client_cert_path (s_8021x), ==, "/test_8021x_cert_read/a.pem");

	g_assert (nm_setting_802_1x_get_private_key_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB);
	_assert_gbytes (nm_setting_802_1x_get_private_key_blob (s_8021x), "hallo", -1);
	CLEAR (&con, &keyfile);

	keyfile = _keyfile_load_from_data (
	          "[connection]\n"
	          "type=802-3-ethernet\n"

	          "[802-1x]\n"
	          "eap=tls;\n"
	          "identity=Bill Smith\n"
	          "ca-cert=file://data:;base64,x\n"
	          "client-cert=abc.der\n"
	          "private-key=abc.deR\n"
	          "private-key-password=12345testing\n"
	          );
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, TRUE);
	s_8021x = nm_connection_get_setting_802_1x (con);

	g_assert (nm_setting_802_1x_get_ca_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert_cmpstr (nm_setting_802_1x_get_ca_cert_path (s_8021x), ==, "data:;base64,x");

	g_assert (nm_setting_802_1x_get_client_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert_cmpstr (nm_setting_802_1x_get_client_cert_path (s_8021x), ==, "/test_8021x_cert_read/abc.der");

	g_assert (nm_setting_802_1x_get_private_key_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB);
	_assert_gbytes (nm_setting_802_1x_get_private_key_blob (s_8021x), "abc.deR\0", 8);
	CLEAR (&con, &keyfile);

	keyfile = _keyfile_load_from_data (
	          "[connection]\n"
	          "type=802-3-ethernet\n"

	          "[802-1x]\n"
	          "eap=tls;\n"
	          "identity=Bill Smith\n"
	          "ca-cert=104;97;108;108;111;\n" /* "hallo" without trailing NUL */
	          "client-cert=104;097;108;108;111;0;\n"
	          "private-key=hallo\n"
	          "private-key-password=12345testing\n"
	          );
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, TRUE);
	s_8021x = nm_connection_get_setting_802_1x (con);

	g_assert (nm_setting_802_1x_get_ca_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB);
	_assert_gbytes (nm_setting_802_1x_get_ca_cert_blob (s_8021x), "hallo", 5);

	g_assert (nm_setting_802_1x_get_client_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB);
	_assert_gbytes (nm_setting_802_1x_get_client_cert_blob (s_8021x), "hallo\0", 6);

	g_assert (nm_setting_802_1x_get_private_key_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB);
	_assert_gbytes (nm_setting_802_1x_get_private_key_blob (s_8021x), "hallo\0", 6);
	CLEAR (&con, &keyfile);
}

static void
test_team_conf_read_valid (void)
{
	GKeyFile *keyfile = NULL;
	gs_unref_object NMConnection *con = NULL;
	NMSettingTeam *s_team;

	con = nmtst_create_connection_from_keyfile (
	      "[connection]\n"
	      "type=team\n"
	      "interface-name=nm-team1\n"
	      "[team]\n"
	      "config={\"foo\":\"bar\"}",
	      "/test_team_conf_read/valid");

	g_assert (con);
	s_team = nm_connection_get_setting_team (con);
	g_assert (s_team);
	g_assert_cmpstr (nm_setting_team_get_config (s_team), ==, "{\"foo\":\"bar\"}");

	CLEAR (&con, &keyfile);
}

static void
test_team_conf_read_invalid (void)
{
	GKeyFile *keyfile = NULL;
	gs_unref_object NMConnection *con = NULL;
	NMSettingTeam *s_team;

	if (!WITH_JSON_VALIDATION) {
		g_test_skip ("team test requires JSON validation");
		return;
	}

	con = nmtst_create_connection_from_keyfile (
	      "[connection]\n"
	      "type=team\n"
	      "interface-name=nm-team1\n"
	      "[team]\n"
	      "config={foobar}",
	      "/test_team_conf_read/invalid");

	g_assert (con);
	s_team = nm_connection_get_setting_team (con);
	g_assert (s_team);
	g_assert (nm_setting_team_get_config (s_team) == NULL);

	CLEAR (&con, &keyfile);
}

/*****************************************************************************/

static void
test_user_1 (void)
{
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	gs_unref_object NMConnection *con = NULL;
	NMSettingUser *s_user;

	con = nmtst_create_connection_from_keyfile (
	      "[connection]\n"
	      "id=t\n"
	      "type=ethernet\n"
	      "\n"
	      "[user]\n"
	      "my-value.x=value1\n"
	      "",
	      "/test_user_1/invalid");
	g_assert (con);
	s_user = NM_SETTING_USER (nm_connection_get_setting (con, NM_TYPE_SETTING_USER));
	g_assert (s_user);
	g_assert_cmpstr (nm_setting_user_get_data (s_user, "my-value.x"), ==, "value1");

	CLEAR (&con, &keyfile);

	con = nmtst_create_minimal_connection ("user-2", "8b85fb8d-3070-48ba-93d9-53eee231d9a2", NM_SETTING_WIRED_SETTING_NAME, NULL);
	s_user = NM_SETTING_USER (nm_setting_user_new ());

#define _USER_SET_DATA(s_user, key, val) \
	G_STMT_START { \
		GError *_error = NULL; \
		gboolean _success; \
		\
		_success = nm_setting_user_set_data ((s_user), (key), (val), &_error); \
		nmtst_assert_success (_success, _error); \
	} G_STMT_END

#define _USER_SET_DATA_X(s_user, key) \
	_USER_SET_DATA (s_user, key, "val="key"")

	_USER_SET_DATA (s_user, "my.val1", "");
	_USER_SET_DATA_X (s_user, "my.val2");
	_USER_SET_DATA_X (s_user, "my.v__al3");
	_USER_SET_DATA_X (s_user, "my._v");
	_USER_SET_DATA_X (s_user, "my.v+");
	_USER_SET_DATA_X (s_user, "my.Av");
	_USER_SET_DATA_X (s_user, "MY.AV");
	_USER_SET_DATA_X (s_user, "MY.8V");
	_USER_SET_DATA_X (s_user, "MY.8-V");
	_USER_SET_DATA_X (s_user, "MY.8_V");
	_USER_SET_DATA_X (s_user, "MY.8+V");
	_USER_SET_DATA_X (s_user, "MY.8/V");
	_USER_SET_DATA_X (s_user, "MY.8=V");
	_USER_SET_DATA_X (s_user, "MY.-");
	_USER_SET_DATA_X (s_user, "MY._");
	_USER_SET_DATA_X (s_user, "MY.+");
	_USER_SET_DATA_X (s_user, "MY./");
	_USER_SET_DATA_X (s_user, "MY.=");
	_USER_SET_DATA_X (s_user, "my.keys.1");
	_USER_SET_DATA_X (s_user, "my.other.KEY.42");

	nm_connection_add_setting (con, NM_SETTING (s_user));
	nmtst_connection_normalize (con);

	_keyfile_convert (&con, &keyfile, "/test_user_1/foo", NULL, NULL, NULL, NULL, FALSE);
}

/*****************************************************************************/

static void
test_vpn_1 (void)
{
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	gs_unref_object NMConnection *con = NULL;
	NMSettingVpn *s_vpn;

	con = nmtst_create_connection_from_keyfile (
	      "[connection]\n"
	      "id=t\n"
	      "type=vpn\n"
	      "\n"
	      "[vpn]\n"
	      "service-type=a.b.c\n"
	      "vpn-key-1=value1\n"
	      "",
	      "/test_vpn_1/invalid");
	g_assert (con);
	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (con, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "vpn-key-1"), ==, "value1");

	CLEAR (&con, &keyfile);
}

/*****************************************************************************/

static void
test_bridge_vlans (void)
{
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	gs_unref_object NMConnection *con = NULL;
	NMSettingBridge *s_bridge;
	NMBridgeVlan *vlan;
	guint16 vid, vid_end;

	con = nmtst_create_connection_from_keyfile (
	      "[connection]\n"
	      "id=t\n"
	      "type=bridge\n"
	      "interface-name=br4\n"
	      "\n"
	      "[bridge]\n"
	      "vlans=900 ,  1 pvid  untagged, 100-123 untagged\n"
	      "",
	      "/test_bridge_port/vlans");
	s_bridge = NM_SETTING_BRIDGE (nm_connection_get_setting (con, NM_TYPE_SETTING_BRIDGE));
	g_assert (s_bridge);
	g_assert_cmpuint (nm_setting_bridge_get_num_vlans (s_bridge), ==, 3);

	vlan = nm_setting_bridge_get_vlan (s_bridge, 0);
	g_assert (vlan);
	nm_bridge_vlan_get_vid_range (vlan, &vid, &vid_end);
	g_assert_cmpuint (vid, ==, 1);
	g_assert_cmpuint (vid_end, ==, 1);
	g_assert_cmpint  (nm_bridge_vlan_is_pvid (vlan), ==, TRUE);
	g_assert_cmpint  (nm_bridge_vlan_is_untagged (vlan), ==, TRUE);

	vlan = nm_setting_bridge_get_vlan (s_bridge, 1);
	g_assert (vlan);
	nm_bridge_vlan_get_vid_range (vlan, &vid, &vid_end);
	g_assert_cmpuint (vid, ==, 100);
	g_assert_cmpuint (vid_end, ==, 123);
	g_assert_cmpint  (nm_bridge_vlan_is_pvid (vlan), ==, FALSE);
	g_assert_cmpint  (nm_bridge_vlan_is_untagged (vlan), ==, TRUE);

	vlan = nm_setting_bridge_get_vlan (s_bridge, 2);
	g_assert (vlan);
	nm_bridge_vlan_get_vid_range (vlan, &vid, &vid_end);
	g_assert_cmpuint (vid, ==, 900);
	g_assert_cmpuint (vid_end, ==, 900);
	g_assert_cmpint  (nm_bridge_vlan_is_pvid (vlan), ==, FALSE);
	g_assert_cmpint  (nm_bridge_vlan_is_untagged (vlan), ==, FALSE);

	CLEAR (&con, &keyfile);
}

static void
test_bridge_port_vlans (void)
{
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	gs_unref_object NMConnection *con = NULL;
	NMSettingBridgePort *s_port;
	NMBridgeVlan *vlan;
	guint16 vid_start, vid_end;

	con = nmtst_create_connection_from_keyfile (
	      "[connection]\n"
	      "id=t\n"
	      "type=dummy\n"
	      "interface-name=dummy1\n"
	      "master=br0\n"
	      "slave-type=bridge\n"
	      "\n"
	      "[bridge-port]\n"
	      "vlans=4094 pvid , 10-20 untagged\n"
	      "",
	      "/test_bridge_port/vlans");
	s_port = NM_SETTING_BRIDGE_PORT (nm_connection_get_setting (con, NM_TYPE_SETTING_BRIDGE_PORT));
	g_assert (s_port);
	g_assert_cmpuint (nm_setting_bridge_port_get_num_vlans (s_port), ==, 2);

	vlan = nm_setting_bridge_port_get_vlan (s_port, 0);
	g_assert (vlan);
	nm_bridge_vlan_get_vid_range (vlan, &vid_start, &vid_end);
	g_assert_cmpuint (vid_start, ==, 10);
	g_assert_cmpuint (vid_end, ==, 20);
	g_assert_cmpint  (nm_bridge_vlan_is_pvid (vlan), ==, FALSE);
	g_assert_cmpint  (nm_bridge_vlan_is_untagged (vlan), ==, TRUE);

	vlan = nm_setting_bridge_port_get_vlan (s_port, 1);
	g_assert (vlan);
	nm_bridge_vlan_get_vid_range (vlan, &vid_start, &vid_end);
	g_assert_cmpuint (vid_start, ==, 4094);
	g_assert_cmpuint (vid_end, ==, 4094);
	g_assert_cmpint  (nm_bridge_vlan_is_pvid (vlan), ==, TRUE);
	g_assert_cmpint  (nm_bridge_vlan_is_untagged (vlan), ==, FALSE);

	CLEAR (&con, &keyfile);
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/core/keyfile/encode_key", test_encode_key);
	g_test_add_func ("/core/keyfile/test_8021x_cert", test_8021x_cert);
	g_test_add_func ("/core/keyfile/test_8021x_cert_tpm2key", test_8021x_cert_tpm2key);
	g_test_add_func ("/core/keyfile/test_8021x_cert_read", test_8021x_cert_read);
	g_test_add_func ("/core/keyfile/test_team_conf_read/valid", test_team_conf_read_valid);
	g_test_add_func ("/core/keyfile/test_team_conf_read/invalid", test_team_conf_read_invalid);
	g_test_add_func ("/core/keyfile/test_user/1", test_user_1);
	g_test_add_func ("/core/keyfile/test_vpn/1", test_vpn_1);
	g_test_add_func ("/core/keyfile/bridge/vlans", test_bridge_vlans);
	g_test_add_func ("/core/keyfile/bridge-port/vlans", test_bridge_port_vlans);

	return g_test_run ();
}

