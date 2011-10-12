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
 */

#include <config.h>

#if !HAVE_POLKIT

#include "nm-polkit.h"

G_DEFINE_TYPE (PolkitAuthority, polkit_authority, G_TYPE_OBJECT);
G_DEFINE_TYPE (PolkitAuthorizationResult, polkit_authorization_result, G_TYPE_OBJECT);

static void polkit_authority_init (PolkitAuthority *self) { }
static void polkit_authorization_result_init (PolkitAuthorizationResult *self) { }
static void polkit_authority_class_init (PolkitAuthorityClass *klass) { }
static void polkit_authorization_result_class_init (PolkitAuthorizationResultClass *klass) { }

#endif /* !HAVE_POLKIT */

