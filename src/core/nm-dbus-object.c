/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-dbus-object.h"

#include "nm-dbus-manager.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

enum {
    EXPORTED_CHANGED,

    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_ABSTRACT_TYPE(NMDBusObject, nm_dbus_object, G_TYPE_OBJECT);

/*****************************************************************************/

#define _NMLOG_DOMAIN LOGD_CORE
#define _NMLOG(level, ...) \
    __NMLOG_DEFAULT_WITH_ADDR(level, _NMLOG_DOMAIN, "dbus-object", __VA_ARGS__)

#define _NMLOG2_DOMAIN LOGD_DBUS_PROPS
#define _NMLOG2(level, ...) \
    __NMLOG_DEFAULT_WITH_ADDR(level, _NMLOG2_DOMAIN, "properties-changed", __VA_ARGS__)

/*****************************************************************************/

static void
_emit_exported_changed(NMDBusObject *self)
{
    g_signal_emit(self, signals[EXPORTED_CHANGED], 0);
}

static char *
_create_export_path(NMDBusObjectClass *klass)
{
    nm_assert(NM_IS_DBUS_OBJECT_CLASS(klass));
    nm_assert(klass->export_path.path);

#if NM_MORE_ASSERTS
    {
        const char *p;

        p = strchr(klass->export_path.path, '%');
        if (klass->export_path.int_counter) {
            nm_assert(p);
            nm_assert(p[1] == 'l');
            nm_assert(p[2] == 'l');
            nm_assert(p[3] == 'u');
            nm_assert(p[4] == '\0');
        } else
            nm_assert(!p);
    }
#endif

    if (klass->export_path.int_counter) {
        NM_PRAGMA_WARNING_DISABLE("-Wformat-nonliteral")
        return g_strdup_printf(klass->export_path.path, ++(*klass->export_path.int_counter));
        NM_PRAGMA_WARNING_REENABLE
    }
    return g_strdup(klass->export_path.path);
}

/**
 * nm_dbus_object_export:
 * @self: an #NMDBusObject
 *
 * Exports @self on all active and future D-Bus connections.
 *
 * The path to export @self on is taken from its #NMObjectClass's %export_path
 * member. If the %export_path contains "%u", then it will be replaced with a
 * monotonically increasing integer ID (with each distinct %export_path having
 * its own counter). Otherwise, %export_path will be used literally (implying
 * that @self must be a singleton).
 *
 * Returns: the path @self was exported under
 */
const char *
nm_dbus_object_export(gpointer /* (NMDBusObject *) */ self)
{
    NMDBusObject * self1      = self;
    static guint64 id_counter = 0;

    g_return_val_if_fail(NM_IS_DBUS_OBJECT(self1), NULL);

    g_return_val_if_fail(!self1->internal.path, self1->internal.path);

    nm_assert(!self1->internal.is_unexporting);

    self1->internal.path = _create_export_path(NM_DBUS_OBJECT_GET_CLASS(self1));

    self1->internal.export_version_id = ++id_counter;

    _LOGT("export: \"%s\"", self1->internal.path);

    _nm_dbus_manager_obj_export(self1);

    _emit_exported_changed(self1);
    return self1->internal.path;
}

/**
 * nm_dbus_object_unexport:
 * @self: an #NMDBusObject
 *
 * Unexports @self on all active D-Bus connections (and prevents it from being
 * auto-exported on future connections).
 */
void
nm_dbus_object_unexport(gpointer /* (NMDBusObject *) */ self)
{
    NMDBusObject *self1 = self;

    g_return_if_fail(NM_IS_DBUS_OBJECT(self1));

    g_return_if_fail(self1->internal.path);

    _LOGT("unexport: \"%s\"", self1->internal.path);

    /* note that we emit the signal *before* actually unexporting the object.
     * The reason is, that listeners want to use this signal to know that
     * the object goes away, and clear their D-Bus path to this object.
     *
     * But this must happen before we actually unregister the object, so
     * that we first emit a D-Bus signal that other objects no longer
     * reference this object, before finally unregistering the object itself.
     *
     * The inconvenient part is, that at this point nm_dbus_object_get_path()
     * still returns the path. So, the callee needs to handle that. Possibly
     * by using "nm_dbus_object_get_path_still_exported()". */
    self1->internal.is_unexporting = TRUE;

    _emit_exported_changed(self1);

    _nm_dbus_manager_obj_unexport(self1);

    nm_clear_g_free(&self1->internal.path);
    self1->internal.export_version_id = 0;

    self1->internal.is_unexporting = FALSE;
}

static gboolean
_unexport_on_idle_cb(gpointer user_data)
{
    gs_unref_object NMDBusObject *self = user_data;

    nm_dbus_object_unexport(self);
    return G_SOURCE_REMOVE;
}

void
nm_dbus_object_unexport_on_idle(gpointer /* (NMDBusObject *) */ self_take)
{
    NMDBusObject *self = g_steal_pointer(&self_take);

    if (!self)
        return;

    g_return_if_fail(NM_IS_DBUS_OBJECT(self));

    g_return_if_fail(self->internal.path);

    /* There is no mechanism to cancel or abort the unexport. It will always
     * gonna happen.
     *
     * However, we register it to block shutdown, so that we ensure that it will happen. */

    nm_shutdown_wait_obj_register_object(self, "unexport-dbus-obj-on-idle");

    /* pass on ownership. */
    g_idle_add(_unexport_on_idle_cb, g_steal_pointer(&self));
}

/*****************************************************************************/

void
_nm_dbus_object_clear_and_unexport(NMDBusObject **location)
{
    NMDBusObject *self;

    g_return_if_fail(location);
    if (!*location)
        return;

    self = g_steal_pointer(location);

    g_return_if_fail(NM_IS_DBUS_OBJECT(self));

    if (self->internal.path)
        nm_dbus_object_unexport(self);

    g_object_unref(self);
}

/*****************************************************************************/

void
nm_dbus_object_emit_signal_variant(NMDBusObject *                     self,
                                   const NMDBusInterfaceInfoExtended *interface_info,
                                   const GDBusSignalInfo *            signal_info,
                                   GVariant *                         args)
{
    if (!self->internal.path) {
        nm_g_variant_unref_floating(args);
        return;
    }
    _nm_dbus_manager_obj_emit_signal(self, interface_info, signal_info, args);
}

void
nm_dbus_object_emit_signal(NMDBusObject *                     self,
                           const NMDBusInterfaceInfoExtended *interface_info,
                           const GDBusSignalInfo *            signal_info,
                           const char *                       format,
                           ...)
{
    va_list ap;

    nm_assert(NM_IS_DBUS_OBJECT(self));
    nm_assert(format);

    if (!self->internal.path)
        return;

    va_start(ap, format);
    _nm_dbus_manager_obj_emit_signal(self,
                                     interface_info,
                                     signal_info,
                                     g_variant_new_va(format, NULL, &ap));
    va_end(ap);
}

/*****************************************************************************/

static void
dispatch_properties_changed(GObject *object, guint n_pspecs, GParamSpec **pspecs)
{
    NMDBusObject *self = NM_DBUS_OBJECT(object);

    if (self->internal.path)
        _nm_dbus_manager_obj_notify(self, n_pspecs, (const GParamSpec *const *) pspecs);

    G_OBJECT_CLASS(nm_dbus_object_parent_class)
        ->dispatch_properties_changed(object, n_pspecs, pspecs);
}

/*****************************************************************************/

static void
nm_dbus_object_init(NMDBusObject *self)
{
    c_list_init(&self->internal.objects_lst);
    c_list_init(&self->internal.registration_lst_head);
    self->internal.bus_manager = nm_g_object_ref(nm_dbus_manager_get());
}

static void
constructed(GObject *object)
{
    NMDBusObjectClass *klass;

    G_OBJECT_CLASS(nm_dbus_object_parent_class)->constructed(object);

    klass = NM_DBUS_OBJECT_GET_CLASS(object);

    if (klass->export_on_construction)
        nm_dbus_object_export((NMDBusObject *) object);

    /* NMDBusObject types should be very careful when overwriting notify().
     * It is possible to do, but this is a reminder that it's probably not
     * a good idea.
     *
     * It's not a good idea, because NMDBusObject uses dispatch_properties_changed()
     * to emit signals about a bunch of property changes. So, we want to make
     * use of g_object_freeze_notify() / g_object_thaw_notify() to combine multiple
     * property changes in one signal on D-Bus. Note that notify() is not invoked
     * while the signal is frozen, that means, whatever you do inside notify()
     * will not make it into the same batch of PropertiesChanged signal. That is
     * confusing, and probably not what you want.
     *
     * Simple solution: don't overwrite notify(). */
    nm_assert(!G_OBJECT_CLASS(klass)->notify);
}

static void
dispose(GObject *object)
{
    NMDBusObject *self = NM_DBUS_OBJECT(object);

    /* Objects should have already been unexported by their owner, unless
     * we are quitting, where many objects stick around until exit.
     */
    if (self->internal.path) {
        if (!nm_dbus_manager_is_stopping(nm_dbus_object_get_manager(self)))
            g_warn_if_reached();
        nm_dbus_object_unexport(self);
    }

    G_OBJECT_CLASS(nm_dbus_object_parent_class)->dispose(object);

    g_clear_object(&self->internal.bus_manager);
}

static void
nm_dbus_object_class_init(NMDBusObjectClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->constructed                 = constructed;
    object_class->dispose                     = dispose;
    object_class->dispatch_properties_changed = dispatch_properties_changed;

    signals[EXPORTED_CHANGED] = g_signal_new(NM_DBUS_OBJECT_EXPORTED_CHANGED,
                                             G_OBJECT_CLASS_TYPE(object_class),
                                             G_SIGNAL_RUN_FIRST,
                                             0,
                                             NULL,
                                             NULL,
                                             g_cclosure_marshal_VOID__VOID,
                                             G_TYPE_NONE,
                                             0);
}
