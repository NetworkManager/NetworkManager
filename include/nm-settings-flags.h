/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef NM_SETTINGS_FLAGS_H
#define NM_SETTINGS_FLAGS_H

/* NOTE: these values should match the NM_SECRET_AGENT_GET_SECRETS_FLAGS in
 * the nm-secret-agent.xml introspection file; except ONLY_SYSTEM which is
 * internal to NM.
 */
typedef enum {
	NM_SETTINGS_GET_SECRETS_FLAG_NONE = 0x0,
	NM_SETTINGS_GET_SECRETS_FLAG_ALLOW_INTERACTION = 0x1,
	NM_SETTINGS_GET_SECRETS_FLAG_REQUEST_NEW = 0x2,
	NM_SETTINGS_GET_SECRETS_FLAG_USER_REQUESTED = 0x4,

	/* Internal only to NM */
	NM_SETTINGS_GET_SECRETS_FLAG_ONLY_SYSTEM = 0x80000000
} NMSettingsGetSecretsFlags;

#endif  /* NM_SETTINGS_FLAGS_H */

