/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_DBUS_UTILS_H__
#define __NM_DBUS_UTILS_H__

/*****************************************************************************/

struct _NMDBusInterfaceInfoExtended;
struct _NMDBusMethodInfoExtended;

struct _NMDBusPropertyInfoExtendedBase {
    GDBusPropertyInfo _parent;
    const char       *property_name;
};

struct _NMDBusPropertyInfoExtendedReadWritable {
    struct _NMDBusPropertyInfoExtendedBase _base;

    /* this is the polkit permission type for authenticating setting
     * the property. */
    const char *permission;

    /* this is the audit operation type for writing the property. */
    const char *audit_op;
};

typedef struct {
    union {
        GDBusPropertyInfo                              _parent;
        struct _NMDBusPropertyInfoExtendedBase         _base;
        struct _NMDBusPropertyInfoExtendedReadWritable writable;

        /* duplicate the base structure in the union, so that the common fields
         * are accessible directly in the parent struct. */
        struct {
            GDBusPropertyInfo parent;
            const char       *property_name;
        };
    };
} NMDBusPropertyInfoExtended;

G_STATIC_ASSERT(G_STRUCT_OFFSET(NMDBusPropertyInfoExtended, property_name)
                == G_STRUCT_OFFSET(struct _NMDBusPropertyInfoExtendedBase, property_name));

#define NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE(m_name, m_signature, m_property_name) \
    ((GDBusPropertyInfo *) &((const struct _NMDBusPropertyInfoExtendedBase){                 \
        ._parent =                                                                           \
            {                                                                                \
                .ref_count = -1,                                                             \
                .name      = m_name,                                                         \
                .signature = m_signature,                                                    \
                .flags     = G_DBUS_PROPERTY_INFO_FLAGS_READABLE,                            \
            },                                                                               \
        .property_name = m_property_name,                                                    \
    }))

#define NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READWRITABLE(m_name,                   \
                                                           m_signature,              \
                                                           m_property_name,          \
                                                           m_permission,             \
                                                           m_audit_op)               \
    ((GDBusPropertyInfo *) &((const struct _NMDBusPropertyInfoExtendedReadWritable){ \
        ._base =                                                                     \
            {                                                                        \
                ._parent =                                                           \
                    {                                                                \
                        .ref_count = -1,                                             \
                        .name      = m_name,                                         \
                        .signature = m_signature,                                    \
                        .flags     = G_DBUS_PROPERTY_INFO_FLAGS_READABLE             \
                                 | G_DBUS_PROPERTY_INFO_FLAGS_WRITABLE,              \
                    },                                                               \
                .property_name = m_property_name,                                    \
            },                                                                       \
        .permission = m_permission,                                                  \
        .audit_op   = m_audit_op,                                                    \
    }))

typedef struct _NMDBusMethodInfoExtended {
    GDBusMethodInfo parent;
    void (*handle)(NMDBusObject                              *obj,
                   const struct _NMDBusInterfaceInfoExtended *interface_info,
                   const struct _NMDBusMethodInfoExtended    *method_info,
                   GDBusConnection                           *connection,
                   const char                                *sender,
                   GDBusMethodInvocation                     *invocation,
                   GVariant                                  *parameters);
    bool allow_during_shutdown;
} NMDBusMethodInfoExtended;

#define NM_DEFINE_DBUS_METHOD_INFO_EXTENDED(parent_, ...) \
    ((GDBusMethodInfo *) (&((const NMDBusMethodInfoExtended){.parent = parent_, __VA_ARGS__})))

typedef struct _NMDBusInterfaceInfoExtended {
    GDBusInterfaceInfo parent;
} NMDBusInterfaceInfoExtended;

#define NM_DBUS_INTERFACE_INFOS(...)                                           \
    ({                                                                         \
        static const NMDBusInterfaceInfoExtended *const _interface_infos[] = { \
            __VA_ARGS__,                                                       \
            NULL,                                                              \
        };                                                                     \
        _interface_infos;                                                      \
    });

/*****************************************************************************/

GDBusPropertyInfo *
nm_dbus_utils_interface_info_lookup_property(const GDBusInterfaceInfo *interface_info,
                                             const char               *property_name,
                                             guint                    *property_idx);

GDBusMethodInfo *
nm_dbus_utils_interface_info_lookup_method(const GDBusInterfaceInfo *interface_info,
                                           const char               *method_name);

GVariant *
nm_dbus_utils_get_property(GObject *obj, const char *signature, const char *property_name);

/*****************************************************************************/

struct CList;

const char **nm_dbus_utils_get_paths_for_clist(const struct CList *lst_head,
                                               gssize              lst_len,
                                               guint               member_offset,
                                               gboolean            expect_all_exported);

void nm_dbus_utils_g_value_set_object_path(GValue *value, gpointer object);

void nm_dbus_utils_g_value_set_object_path_still_exported(GValue *value, gpointer object);

void nm_dbus_utils_g_value_set_object_path_from_hash(GValue     *value,
                                                     GHashTable *hash,
                                                     gboolean    expect_all_exported);

/*****************************************************************************/

typedef struct {
    union {
        gpointer const obj;
        gpointer       _obj;
    };
    GObject          *_notify_target;
    const GParamSpec *_notify_pspec;
    gulong            _notify_signal_id;
    union {
        const bool visible;
        bool       _visible;
    };
} NMDBusTrackObjPath;

void
nm_dbus_track_obj_path_init(NMDBusTrackObjPath *track, GObject *target, const GParamSpec *pspec);

void nm_dbus_track_obj_path_deinit(NMDBusTrackObjPath *track);

void nm_dbus_track_obj_path_notify(const NMDBusTrackObjPath *track);

const char *nm_dbus_track_obj_path_get(const NMDBusTrackObjPath *track);

void nm_dbus_track_obj_path_set(NMDBusTrackObjPath *track, gpointer obj, gboolean visible);

#endif /* __NM_DBUS_UTILS_H__ */
