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
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-metadata.h"

/*****************************************************************************/

const NMSetting8021xSchemeVtable nm_setting_8021x_scheme_vtable[] = {
	[NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT] = {
		.setting_key            = NM_SETTING_802_1X_CA_CERT,
		.scheme_func            = nm_setting_802_1x_get_ca_cert_scheme,
		.format_func            = NULL,
		.path_func              = nm_setting_802_1x_get_ca_cert_path,
		.blob_func              = nm_setting_802_1x_get_ca_cert_blob,
		.uri_func               = nm_setting_802_1x_get_ca_cert_uri,
		.passwd_func            = nm_setting_802_1x_get_ca_cert_password,
		.pwflag_func            = nm_setting_802_1x_get_ca_cert_password_flags,
		.file_suffix            = "ca-cert",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT] = {
		.setting_key            = NM_SETTING_802_1X_PHASE2_CA_CERT,
		.scheme_func            = nm_setting_802_1x_get_phase2_ca_cert_scheme,
		.format_func            = NULL,
		.path_func              = nm_setting_802_1x_get_phase2_ca_cert_path,
		.blob_func              = nm_setting_802_1x_get_phase2_ca_cert_blob,
		.uri_func               = nm_setting_802_1x_get_phase2_ca_cert_uri,
		.passwd_func            = nm_setting_802_1x_get_phase2_ca_cert_password,
		.pwflag_func            = nm_setting_802_1x_get_phase2_ca_cert_password_flags,
		.file_suffix            = "inner-ca-cert",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT] = {
		.setting_key            = NM_SETTING_802_1X_CLIENT_CERT,
		.scheme_func            = nm_setting_802_1x_get_client_cert_scheme,
		.format_func            = NULL,
		.path_func              = nm_setting_802_1x_get_client_cert_path,
		.blob_func              = nm_setting_802_1x_get_client_cert_blob,
		.uri_func               = nm_setting_802_1x_get_client_cert_uri,
		.passwd_func            = nm_setting_802_1x_get_client_cert_password,
		.pwflag_func            = nm_setting_802_1x_get_client_cert_password_flags,
		.file_suffix            = "client-cert",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT] = {
		.setting_key            = NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
		.scheme_func            = nm_setting_802_1x_get_phase2_client_cert_scheme,
		.format_func            = NULL,
		.path_func              = nm_setting_802_1x_get_phase2_client_cert_path,
		.blob_func              = nm_setting_802_1x_get_phase2_client_cert_blob,
		.uri_func               = nm_setting_802_1x_get_phase2_client_cert_uri,
		.passwd_func            = nm_setting_802_1x_get_phase2_client_cert_password,
		.pwflag_func            = nm_setting_802_1x_get_phase2_client_cert_password_flags,
		.file_suffix            = "inner-client-cert",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY] = {
		.setting_key            = NM_SETTING_802_1X_PRIVATE_KEY,
		.scheme_func            = nm_setting_802_1x_get_private_key_scheme,
		.format_func            = nm_setting_802_1x_get_private_key_format,
		.path_func              = nm_setting_802_1x_get_private_key_path,
		.blob_func              = nm_setting_802_1x_get_private_key_blob,
		.uri_func               = nm_setting_802_1x_get_private_key_uri,
		.passwd_func            = nm_setting_802_1x_get_private_key_password,
		.pwflag_func            = nm_setting_802_1x_get_private_key_password_flags,
		.file_suffix            = "private-key",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY] = {
		.setting_key            = NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
		.scheme_func            = nm_setting_802_1x_get_phase2_private_key_scheme,
		.format_func            = nm_setting_802_1x_get_phase2_private_key_format,
		.path_func              = nm_setting_802_1x_get_phase2_private_key_path,
		.blob_func              = nm_setting_802_1x_get_phase2_private_key_blob,
		.uri_func               = nm_setting_802_1x_get_phase2_private_key_uri,
		.passwd_func            = nm_setting_802_1x_get_phase2_private_key_password,
		.pwflag_func            = nm_setting_802_1x_get_phase2_private_key_password_flags,
		.file_suffix            = "inner-private-key",
	},

	[NM_SETTING_802_1X_SCHEME_TYPE_UNKNOWN] = { NULL },
};

/*****************************************************************************/
