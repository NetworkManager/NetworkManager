/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#include "nm-test-utils.h"


#define TEST_WIRED_TLS_CA_CERT     TEST_CERT_DIR"/test-ca-cert.pem"
#define TEST_WIRED_TLS_PRIVKEY     TEST_CERT_DIR"/test-key-and-cert.pem"


/******************************************************************************/

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
	else {
		g_assert_cmpint (g_bytes_get_size (bytes), ==, len);
		g_assert (memcmp (g_bytes_get_data (bytes, NULL), data, len) == 0);
	}
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
                  const char *base_dir,
                  NMKeyfileReadHandler read_handler,
                  void *read_data,
                  gboolean needs_normalization)
{
	GError *error = NULL;
	NMConnection *con;

	g_assert (keyfile);

	con = nm_keyfile_read (keyfile, keyfile_name, base_dir, read_handler, read_data, &error);
	g_assert_no_error (error);
	g_assert (NM_IS_CONNECTION (con));
	if (needs_normalization) {
		nmtst_assert_connection_verifies_after_normalization (con, 0, 0);
		nmtst_connection_normalize (con);
	} else
		nmtst_assert_connection_verifies_without_normalization (con);
	return con;
}


static void
_keyfile_convert (NMConnection **con,
                  GKeyFile **keyfile,
                  const char *keyfile_name,
                  const char *base_dir,
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
		c0_k1_c2 = _nm_keyfile_read (c0_k1, keyfile_name, base_dir, read_handler, read_data, FALSE);
		c0_k1_c2_k3 = _nm_keyfile_write (c0_k1_c2, write_handler, write_data);

		g_assert (_nm_keyfile_equals (c0_k1, c0_k1_c2_k3, TRUE));
	}
	if (k0) {
		NMSetting8021x *s1, *s2;

		k0_c1 = _nm_keyfile_read (k0, keyfile_name, base_dir, read_handler, read_data, needs_normalization);
		k0_c1_k2 = _nm_keyfile_write (k0_c1, write_handler, write_data);
		k0_c1_k2_c3 = _nm_keyfile_read (k0_c1_k2, keyfile_name, base_dir, read_handler, read_data, FALSE);

		/* It is a expeced behavior, that if @k0 contains a relative path ca-cert, @k0_c1 will
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
				g_assert_cmpint (g_bytes_get_size (b1), ==, g_bytes_get_size (b2));
				g_assert (memcmp (g_bytes_get_data (b1, NULL), g_bytes_get_data (b2, NULL), g_bytes_get_size (b1)) == 0);
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

/******************************************************************************/

static void
_test_8021x_cert_check (NMConnection *con,
                        NMSetting8021xCKScheme expected_scheme,
                        const void *value,
                        gssize val_len)
{
	GKeyFile *keyfile = NULL;
	NMSetting8021x *s_8021x;
	gs_free char *kval = NULL;

	_keyfile_convert (&con, &keyfile, NULL, NULL, NULL, NULL, NULL, NULL, FALSE);

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
		g_assert_cmpint (g_bytes_get_size (blob), ==, val_len);
		g_assert (!memcmp (g_bytes_get_data (blob, NULL), value, val_len));

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
test_8021x_cert (void)
{
	NMSetting8021x *s_8021x;
	gs_unref_object NMConnection *con = nmtst_create_minimal_connection ("test-cert", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	GError *error = NULL;
	gboolean success;
	NMSetting8021xCKScheme scheme = NM_SETTING_802_1X_CK_SCHEME_PATH;
	gs_free char *full_TEST_WIRED_TLS_CA_CERT = nmtst_file_resolve_relative_path (TEST_WIRED_TLS_CA_CERT, NULL);
	gs_free char *full_TEST_WIRED_TLS_PRIVKEY = nmtst_file_resolve_relative_path (TEST_WIRED_TLS_PRIVKEY, NULL);

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


	/* test reseting ca-cert to different values and see whether we can write/read. */

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

/******************************************************************************/

static void
test_8021x_cert_read (void)
{
	GKeyFile *keyfile = NULL;
	gs_unref_object NMConnection *con = NULL;
	NMSetting8021x *s_8021x;

	con = nmtst_create_connection_from_keyfile (
	      "[connection]\n"
	      "type=ethernet",
	      "/test_8021x_cert_read/test0", NULL);
	CLEAR (&con, &keyfile);


	keyfile = _keyfile_load_from_data (
	          "[connection]\n"
	          "type=ethernet"
	          );
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test1", NULL, NULL, NULL, NULL, NULL, TRUE);
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
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, NULL, TRUE);
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
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, NULL, TRUE);
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
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, NULL, TRUE);
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
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, NULL, TRUE);
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
	_keyfile_convert (&con, &keyfile, "/test_8021x_cert_read/test2", NULL, NULL, NULL, NULL, NULL, TRUE);
	s_8021x = nm_connection_get_setting_802_1x (con);

	g_assert (nm_setting_802_1x_get_ca_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB);
	_assert_gbytes (nm_setting_802_1x_get_ca_cert_blob (s_8021x), "hallo", 5);

	g_assert (nm_setting_802_1x_get_client_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB);
	_assert_gbytes (nm_setting_802_1x_get_client_cert_blob (s_8021x), "hallo\0", 6);

	g_assert (nm_setting_802_1x_get_private_key_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_BLOB);
	_assert_gbytes (nm_setting_802_1x_get_private_key_blob (s_8021x), "hallo\0", 6);
	CLEAR (&con, &keyfile);
}

/******************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/core/keyfile/test_8021x_cert", test_8021x_cert);
	g_test_add_func ("/core/keyfile/test_8021x_cert_read", test_8021x_cert_read);

	return g_test_run ();
}

