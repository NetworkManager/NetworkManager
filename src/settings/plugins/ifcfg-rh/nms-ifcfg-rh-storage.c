/* NetworkManager
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
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-ifcfg-rh-storage.h"

#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-connection.h"
#include "nms-ifcfg-rh-plugin.h"

/*****************************************************************************/

struct _NMSIfcfgRHStorageClass {
	NMSettingsStorageClass parent;
};

G_DEFINE_TYPE (NMSIfcfgRHStorage, nms_ifcfg_rh_storage, NM_TYPE_SETTINGS_STORAGE)

/*****************************************************************************/

gboolean
nms_ifcfg_rh_storage_equal_type (const NMSIfcfgRHStorage *self_a,
                                 const NMSIfcfgRHStorage *self_b)
{
	return    (self_a == self_b)
	       || (   self_a
	           && self_b
	           && nm_streq0 (nms_ifcfg_rh_storage_get_uuid_opt (self_a),
	                         nms_ifcfg_rh_storage_get_uuid_opt (self_b))
	           && nm_streq0 (self_a->unmanaged_spec,
	                         self_b->unmanaged_spec)
	           && nm_streq0 (self_a->unrecognized_spec,
	                         self_b->unrecognized_spec));
}

void
nms_ifcfg_rh_storage_copy_content (NMSIfcfgRHStorage *dst,
                                   const NMSIfcfgRHStorage *src)
{
	nm_assert (src != dst);
	nm_assert (src && dst);
	nm_assert (nms_ifcfg_rh_storage_equal_type (dst, src));
	nm_assert (   nms_ifcfg_rh_storage_get_filename (dst)
	           && nm_streq (nms_ifcfg_rh_storage_get_filename (dst),
	                        nms_ifcfg_rh_storage_get_filename (src)));

	nm_g_object_ref_set (&dst->connection, src->connection);
	g_free (dst->unmanaged_spec);
	g_free (dst->unrecognized_spec);
	dst->unmanaged_spec    = g_strdup (src->unmanaged_spec);
	dst->unrecognized_spec = g_strdup (src->unrecognized_spec);
	dst->stat_mtime        = src->stat_mtime;
}

NMConnection *
nms_ifcfg_rh_storage_steal_connection (NMSIfcfgRHStorage *self)
{
	nm_assert (NMS_IS_IFCFG_RH_STORAGE (self));

	return g_steal_pointer (&self->connection);
}

/*****************************************************************************/

static int
cmp_fcn (const NMSIfcfgRHStorage *a,
         const NMSIfcfgRHStorage *b)
{
	nm_assert (NMS_IS_IFCFG_RH_STORAGE (a));
	nm_assert (NMS_IS_IFCFG_RH_STORAGE (b));
	nm_assert (a != b);

	/* newer files are more important. */
	NM_CMP_FIELD (a, b, stat_mtime.tv_sec);
	NM_CMP_FIELD (a, b, stat_mtime.tv_nsec);

	NM_CMP_DIRECT_STRCMP (nms_ifcfg_rh_storage_get_filename (a), nms_ifcfg_rh_storage_get_filename (b));

	return 0;
}

/*****************************************************************************/

static void
nms_ifcfg_rh_storage_init (NMSIfcfgRHStorage *self)
{
}

static NMSIfcfgRHStorage *
_storage_new (NMSIfcfgRHPlugin *plugin,
              const char *uuid,
              const char *filename)
{
	nm_assert (NMS_IS_IFCFG_RH_PLUGIN (plugin));
	nm_assert (!uuid || nm_utils_is_uuid (uuid));
	nm_assert (filename && filename[0] == '/');

	return g_object_new (NMS_TYPE_IFCFG_RH_STORAGE,
	                     NM_SETTINGS_STORAGE_PLUGIN, plugin,
	                     NM_SETTINGS_STORAGE_UUID, uuid,
	                     NM_SETTINGS_STORAGE_FILENAME, filename,
	                     NULL);
}

NMSIfcfgRHStorage *
nms_ifcfg_rh_storage_new_connection (NMSIfcfgRHPlugin *plugin,
                                     const char *filename,
                                     NMConnection *connection_take,
                                     const struct timespec *mtime)
{
	NMSIfcfgRHStorage *self;

	nm_assert (NM_IS_CONNECTION (connection_take));
	nm_assert (_nm_connection_verify (connection_take, NULL) == NM_SETTING_VERIFY_SUCCESS);
	nmtst_connection_assert_unchanging (connection_take);

	self = _storage_new (plugin,
	                     nm_connection_get_uuid (connection_take),
	                     filename);
	self->connection = connection_take;
	if (mtime)
		self->stat_mtime = *mtime;
	return self;
}

NMSIfcfgRHStorage *
nms_ifcfg_rh_storage_new_unhandled (NMSIfcfgRHPlugin *plugin,
                                    const char *filename,
                                    const char *unmanaged_spec,
                                    const char *unrecognized_spec)
{
	NMSIfcfgRHStorage *self;

	nm_assert (unmanaged_spec || unrecognized_spec);

	self = _storage_new (plugin,
	                     NULL,
	                     filename);
	self->unmanaged_spec = g_strdup (unmanaged_spec);
	self->unrecognized_spec = g_strdup (unrecognized_spec);
	return self;
}

static void
_storage_clear (NMSIfcfgRHStorage *self)
{
	c_list_unlink (&self->parent._storage_lst);
	c_list_unlink (&self->parent._storage_by_uuid_lst);
	nm_clear_g_free (&self->unmanaged_spec);
	nm_clear_g_free (&self->unrecognized_spec);
	g_clear_object (&self->connection);
}

static void
dispose (GObject *object)
{
	NMSIfcfgRHStorage *self = NMS_IFCFG_RH_STORAGE (object);

	_storage_clear (self);

	G_OBJECT_CLASS (nms_ifcfg_rh_storage_parent_class)->dispose (object);
}

void
nms_ifcfg_rh_storage_destroy (NMSIfcfgRHStorage *self)
{
	_storage_clear (self);
	g_object_unref (self);
}

static void
nms_ifcfg_rh_storage_class_init (NMSIfcfgRHStorageClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingsStorageClass *storage_class = NM_SETTINGS_STORAGE_CLASS (klass);

	object_class->dispose = dispose;

	storage_class->cmp_fcn = (int (*) (NMSettingsStorage *, NMSettingsStorage *)) cmp_fcn;
}
