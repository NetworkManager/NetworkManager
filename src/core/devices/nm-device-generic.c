/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013-2023 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-generic.h"

#include "nm-device-private.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-dispatcher.h"
#include "nm-device-factory.h"

#define _NMLOG_DEVICE_TYPE NMDeviceGeneric
#include "devices/nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_TYPE_DESCRIPTION, PROP_IS_SOFTWARE, );

typedef struct {
    const char *type_description;
    bool        prepare_done : 1;
    bool        is_software : 1;
    struct {
        NMDispatcherCallId        *dispatcher_call_id;
        NMDeviceDeactivateCallback callback;
        gpointer                   callback_data;
        GCancellable              *cancellable;
        gulong                     cancellable_id;
    } deactivate;
} NMDeviceGenericPrivate;

struct _NMDeviceGeneric {
    NMDevice               parent;
    NMDeviceGenericPrivate _priv;
};

struct _NMDeviceGenericClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceGeneric, nm_device_generic, NM_TYPE_DEVICE)

#define NM_DEVICE_GENERIC_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceGeneric, NM_IS_DEVICE_GENERIC, NMDevice)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    NMDeviceGenericPrivate *priv    = NM_DEVICE_GENERIC_GET_PRIVATE(device);
    int                     ifindex = nm_device_get_ifindex(device);
    NMDeviceCapabilities    cap     = NM_DEVICE_CAP_NONE;

    if (priv->is_software)
        cap |= NM_DEVICE_CAP_IS_SOFTWARE;

    if (ifindex > 0
        && nm_platform_link_supports_carrier_detect(nm_device_get_platform(device), ifindex))
        cap |= NM_DEVICE_CAP_CARRIER_DETECT;

    return cap;
}

static void
device_add_dispatcher_cb(NMDispatcherCallId *call_id,
                         gpointer            user_data,
                         gboolean            success,
                         const char         *msg)
{
    nm_auto_unref_object NMDeviceGeneric *self     = NM_DEVICE_GENERIC(user_data);
    NMDeviceGenericPrivate               *priv     = NM_DEVICE_GENERIC_GET_PRIVATE(self);
    NMDevice                             *device   = NM_DEVICE(self);
    NMPlatform                           *platform = nm_device_get_platform(device);
    const NMPlatformLink                 *link;
    int                                   ifindex = -1;

    nm_assert(call_id == priv->deactivate.dispatcher_call_id);
    priv->deactivate.dispatcher_call_id = NULL;

    if (!success) {
        _LOGW(LOGD_CORE, "device handler 'device-add' failed: %s", msg);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_DEVICE_HANDLER_FAILED);
        return;
    }

    if (msg) {
        gs_strfreev char **tokens = NULL;
        const char        *ifindex_str;
        guint              i;

        /* Extract the ifindex from the handler output */
        tokens = g_strsplit(msg, "\n", 10);
        for (i = 0; tokens[i]; i++) {
            if (NM_STR_HAS_PREFIX(tokens[i], "IFINDEX=")) {
                ifindex_str = tokens[i] + NM_STRLEN("IFINDEX=");
                ifindex     = _nm_utils_ascii_str_to_int64(ifindex_str, 10, 1, G_MAXINT32, -1);
                if (ifindex < 0) {
                    _LOGW(LOGD_CORE,
                          "device handler 'device-add' returned invalid ifindex '%s'",
                          ifindex_str);
                    nm_device_state_changed(device,
                                            NM_DEVICE_STATE_FAILED,
                                            NM_DEVICE_STATE_REASON_DEVICE_HANDLER_FAILED);
                    return;
                }
                break;
            }
        }
    }

    if (ifindex < 0) {
        _LOGW(LOGD_DEVICE, "device handler 'device-add' returned no ifindex");
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_DEVICE_HANDLER_FAILED);
        return;
    } else {
        _LOGD(LOGD_DEVICE, "device handler 'device-add' returned ifindex %d", ifindex);
        /* Check that the ifindex is valid and matches the interface name. */
        nm_platform_process_events(platform);
        link = nm_platform_link_get(platform, ifindex);
        if (!link) {
            _LOGW(LOGD_DEVICE,
                  "device handler 'device-add' didn't create link with ifindex %d",
                  ifindex);
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_DEVICE_HANDLER_FAILED);
            return;
        } else if (!nm_streq(link->name, nm_device_get_iface(device))) {
            _LOGW(
                LOGD_DEVICE,
                "device handler 'device-add' created a kernel link with name '%s' instead of '%s'",
                link->name,
                nm_device_get_iface(device));
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_DEVICE_HANDLER_FAILED);
            return;
        }
    }

    priv->prepare_done = TRUE;
    nm_device_activate_schedule_stage1_device_prepare(device, FALSE);
}

static NMActStageReturn
act_stage1_prepare(NMDevice *self, NMDeviceStateReason *out_failure_reason)
{
    NMDevice               *device = NM_DEVICE(self);
    NMDeviceGenericPrivate *priv   = NM_DEVICE_GENERIC_GET_PRIVATE(device);
    NMSettingGeneric       *s_generic;

    s_generic = nm_device_get_applied_setting(device, NM_TYPE_SETTING_GENERIC);
    if (!s_generic || !nm_setting_generic_get_device_handler(s_generic))
        return NM_ACT_STAGE_RETURN_SUCCESS;

    if (priv->prepare_done)
        return NM_ACT_STAGE_RETURN_SUCCESS;

    if (priv->deactivate.dispatcher_call_id) {
        nm_dispatcher_call_cancel(priv->deactivate.dispatcher_call_id);
        priv->deactivate.dispatcher_call_id = NULL;
    }

    _LOGD(LOGD_CORE, "calling device handler 'device-add'");
    if (!nm_dispatcher_call_device_handler(NM_DISPATCHER_ACTION_DEVICE_ADD,
                                           device,
                                           NULL,
                                           device_add_dispatcher_cb,
                                           g_object_ref(self),
                                           &priv->deactivate.dispatcher_call_id)) {
        _LOGW(LOGD_DEVICE, "failed to call device handler 'device-add'");
        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_DEVICE_HANDLER_FAILED);
        return NM_ACT_STAGE_RETURN_FAILURE;
    }

    return NM_ACT_STAGE_RETURN_POSTPONE;
}

static gboolean
ready_for_ip_config(NMDevice *device, gboolean is_manual)
{
    return nm_device_get_ifindex(device) > 0;
}

static void
act_stage3_ip_config(NMDevice *device, int addr_family)
{
    nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_READY, NULL);
}

static const char *
get_type_description(NMDevice *device)
{
    if (NM_DEVICE_GENERIC_GET_PRIVATE(device)->type_description)
        return NM_DEVICE_GENERIC_GET_PRIVATE(device)->type_description;
    return NM_DEVICE_CLASS(nm_device_generic_parent_class)->get_type_description(device);
}

static void
realize_start_notify(NMDevice *device, const NMPlatformLink *plink)
{
    NMDeviceGeneric        *self = NM_DEVICE_GENERIC(device);
    NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE(self);
    int                     ifindex;

    NM_DEVICE_CLASS(nm_device_generic_parent_class)->realize_start_notify(device, plink);

    ifindex = nm_device_get_ip_ifindex(NM_DEVICE(self));
    if (ifindex > 0) {
        priv->type_description =
            nm_platform_link_get_type_name(nm_device_get_platform(device), ifindex);
    }
}

static gboolean
check_connection_compatible(NMDevice     *device,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMSettingConnection *s_con;

    if (!NM_DEVICE_CLASS(nm_device_generic_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
        return FALSE;

    s_con = nm_connection_get_setting_connection(connection);
    if (!nm_setting_connection_get_interface_name(s_con)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "generic profiles need an interface name");
        return FALSE;
    }

    return TRUE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMSettingConnection *s_con;

    if (!nm_connection_get_setting_generic(connection))
        nm_connection_add_setting(connection, nm_setting_generic_new());

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_object_set(G_OBJECT(s_con),
                 NM_SETTING_CONNECTION_INTERFACE_NAME,
                 nm_device_get_iface(device),
                 NULL);
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    /* The actual interface is created during stage1 once the device
     * starts activating, as we need to call the dispatcher service
     * which returns asynchronously */
    return TRUE;
}

static void
deactivate_clear_data(NMDeviceGeneric *self)
{
    NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE(self);

    if (priv->deactivate.dispatcher_call_id) {
        nm_dispatcher_call_cancel(priv->deactivate.dispatcher_call_id);
        priv->deactivate.dispatcher_call_id = NULL;
    }

    priv->deactivate.callback      = NULL;
    priv->deactivate.callback_data = NULL;
    g_clear_object(&priv->deactivate.cancellable);
}

static void
device_delete_dispatcher_cb(NMDispatcherCallId *call_id,
                            gpointer            user_data,
                            gboolean            success,
                            const char         *msg)
{
    NMDeviceGeneric        *self  = user_data;
    NMDeviceGenericPrivate *priv  = NM_DEVICE_GENERIC_GET_PRIVATE(self);
    gs_free_error GError   *error = NULL;

    nm_assert(call_id == priv->deactivate.dispatcher_call_id);
    priv->deactivate.dispatcher_call_id = NULL;

    if (success)
        _LOGT(LOGD_DEVICE, "deactivate: async callback");
    else {
        error = g_error_new(NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_FAILED,
                            "device handler 'device-delete' failed with error: %s",
                            msg);
    }

    priv->deactivate.callback(NM_DEVICE(self), error, priv->deactivate.callback_data);
    nm_clear_g_cancellable_disconnect(priv->deactivate.cancellable,
                                      &priv->deactivate.cancellable_id);
    deactivate_clear_data(self);
}

static void
deactivate_cancellable_cancelled(GCancellable *cancellable, NMDeviceGeneric *self)
{
    NMDeviceGenericPrivate *priv  = NM_DEVICE_GENERIC_GET_PRIVATE(self);
    gs_free_error GError   *error = NULL;

    error = nm_utils_error_new_cancelled(FALSE, NULL);
    priv->deactivate.callback(NM_DEVICE(self), error, priv->deactivate.callback_data);

    deactivate_clear_data(self);
}

static void
deactivate_async(NMDevice                  *device,
                 GCancellable              *cancellable,
                 NMDeviceDeactivateCallback callback,
                 gpointer                   callback_user_data)
{
    NMDeviceGeneric        *self = NM_DEVICE_GENERIC(device);
    NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE(self);

    _LOGT(LOGD_CORE, "deactivate: start async");

    priv->prepare_done = FALSE;

    if (priv->deactivate.dispatcher_call_id) {
        nm_dispatcher_call_cancel(priv->deactivate.dispatcher_call_id);
        priv->deactivate.dispatcher_call_id = NULL;
    }

    g_object_ref(self);
    priv->deactivate.callback      = callback;
    priv->deactivate.callback_data = callback_user_data;
    priv->deactivate.cancellable   = g_object_ref(cancellable);
    priv->deactivate.cancellable_id =
        g_cancellable_connect(cancellable,
                              G_CALLBACK(deactivate_cancellable_cancelled),
                              self,
                              NULL);

    nm_dispatcher_call_device_handler(NM_DISPATCHER_ACTION_DEVICE_DELETE,
                                      device,
                                      NULL,
                                      device_delete_dispatcher_cb,
                                      self,
                                      &priv->deactivate.dispatcher_call_id);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceGeneric        *self = NM_DEVICE_GENERIC(object);
    NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_TYPE_DESCRIPTION:
        g_value_set_string(value, priv->type_description);
        break;
    case PROP_IS_SOFTWARE:
        g_value_set_boolean(value, priv->is_software);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMDeviceGeneric        *self = (NMDeviceGeneric *) object;
    NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_IS_SOFTWARE:
        /* construct-only */
        priv->is_software = g_value_get_boolean(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_generic_init(NMDeviceGeneric *self)
{}

static GObject *
constructor(GType type, guint n_construct_params, GObjectConstructParam *construct_params)
{
    GObject                *object;
    NMDeviceGenericPrivate *priv;

    object = G_OBJECT_CLASS(nm_device_generic_parent_class)
                 ->constructor(type, n_construct_params, construct_params);

    priv = NM_DEVICE_GENERIC_GET_PRIVATE(object);
    /* If the device is software (has a device-handler), don't set
     * unmanaged-by-default so that the device can autoconnect if
     * necessary. */
    if (!priv->is_software)
        nm_device_set_unmanaged_flags((NMDevice *) object, NM_UNMANAGED_BY_DEFAULT, TRUE);

    return object;
}

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_GENERIC,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "Generic",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_GENERIC,
                        NM_DEVICE_GENERIC_IS_SOFTWARE,
                        TRUE,
                        NULL);
}

NMDevice *
nm_device_generic_new(const NMPlatformLink *plink, gboolean nm_plugin_missing)
{
    g_return_val_if_fail(plink != NULL, NULL);

    return g_object_new(NM_TYPE_DEVICE_GENERIC,
                        NM_DEVICE_IFACE,
                        plink->name,
                        NM_DEVICE_TYPE_DESC,
                        "Generic",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_GENERIC,
                        NM_DEVICE_NM_PLUGIN_MISSING,
                        nm_plugin_missing,
                        NULL);
}

static const NMDBusInterfaceInfoExtended interface_info_device_generic = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_GENERIC,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("HwAddress", "s", NM_DEVICE_HW_ADDRESS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE(
                "TypeDescription",
                "s",
                NM_DEVICE_GENERIC_TYPE_DESCRIPTION), ), ),
};

static void
nm_device_generic_class_init(NMDeviceGenericClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->constructor  = constructor;
    object_class->get_property = get_property;
    object_class->set_property = set_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_generic);

    device_class->connection_type_supported        = NM_SETTING_GENERIC_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_GENERIC_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_ANY);

    device_class->act_stage1_prepare          = act_stage1_prepare;
    device_class->act_stage3_ip_config        = act_stage3_ip_config;
    device_class->check_connection_compatible = check_connection_compatible;
    device_class->create_and_realize          = create_and_realize;
    device_class->deactivate_async            = deactivate_async;
    device_class->get_generic_capabilities    = get_generic_capabilities;
    device_class->get_type_description        = get_type_description;
    device_class->ready_for_ip_config         = ready_for_ip_config;
    device_class->realize_start_notify        = realize_start_notify;
    device_class->update_connection           = update_connection;

    obj_properties[PROP_TYPE_DESCRIPTION] =
        g_param_spec_string(NM_DEVICE_GENERIC_TYPE_DESCRIPTION,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_IS_SOFTWARE] = g_param_spec_boolean(
        NM_DEVICE_GENERIC_IS_SOFTWARE,
        "",
        "",
        FALSE,
        G_PARAM_READABLE | G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    GENERIC,
    Generic,
    generic,
    NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_GENERIC_SETTING_NAME),
    factory_class->create_device = create_device;);
