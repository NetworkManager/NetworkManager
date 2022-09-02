/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2018 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-serial.h"

#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-serial
 * @short_description: Describes connection properties for devices that use
 * serial communications
 *
 * The #NMSettingSerial object is a #NMSetting subclass that describes
 * properties necessary for connections that may use serial communications,
 * such as mobile broadband or analog telephone connections.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_BAUD,
                                  PROP_BITS,
                                  PROP_PARITY,
                                  PROP_STOPBITS,
                                  PROP_SEND_DELAY, );

typedef struct {
    guint64 send_delay;
    guint32 baud;
    guint32 bits;
    guint32 stopbits;
    char    parity;
} NMSettingSerialPrivate;

/**
 * NMSettingSerial:
 *
 * Serial Link Settings
 */
struct _NMSettingSerial {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingSerialClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingSerial, nm_setting_serial, NM_TYPE_SETTING)

#define NM_SETTING_SERIAL_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_SERIAL, NMSettingSerialPrivate))

/*****************************************************************************/

/**
 * nm_setting_serial_get_baud:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:baud property of the setting
 **/
guint
nm_setting_serial_get_baud(NMSettingSerial *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_SERIAL(setting), 0);

    return NM_SETTING_SERIAL_GET_PRIVATE(setting)->baud;
}

/**
 * nm_setting_serial_get_bits:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:bits property of the setting
 **/
guint
nm_setting_serial_get_bits(NMSettingSerial *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_SERIAL(setting), 0);

    return NM_SETTING_SERIAL_GET_PRIVATE(setting)->bits;
}

/**
 * nm_setting_serial_get_parity:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:parity property of the setting
 **/
NMSettingSerialParity
nm_setting_serial_get_parity(NMSettingSerial *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_SERIAL(setting), 0);

    return NM_SETTING_SERIAL_GET_PRIVATE(setting)->parity;
}

/**
 * nm_setting_serial_get_stopbits:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:stopbits property of the setting
 **/
guint
nm_setting_serial_get_stopbits(NMSettingSerial *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_SERIAL(setting), 0);

    return NM_SETTING_SERIAL_GET_PRIVATE(setting)->stopbits;
}

/**
 * nm_setting_serial_get_send_delay:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:send-delay property of the setting
 **/
guint64
nm_setting_serial_get_send_delay(NMSettingSerial *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_SERIAL(setting), 0);

    return NM_SETTING_SERIAL_GET_PRIVATE(setting)->send_delay;
}

/*****************************************************************************/

static GVariant *
parity_to_dbus_fcn(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    switch (nm_setting_serial_get_parity(NM_SETTING_SERIAL(setting))) {
    case NM_SETTING_SERIAL_PARITY_EVEN:
        return g_variant_new_byte('E');
    case NM_SETTING_SERIAL_PARITY_ODD:
        return g_variant_new_byte('o');
    case NM_SETTING_SERIAL_PARITY_NONE:
        /* the default, serializes to NULL. */
        return NULL;
    default:
        return NULL;
    }
}

static void
parity_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_GPROP_FCN_ARGS _nm_nil)
{
    switch (g_variant_get_byte(from)) {
    case 'E':
        g_value_set_enum(to, NM_SETTING_SERIAL_PARITY_EVEN);
        break;
    case 'o':
        g_value_set_enum(to, NM_SETTING_SERIAL_PARITY_ODD);
        break;
    case 'n':
    default:
        g_value_set_enum(to, NM_SETTING_SERIAL_PARITY_NONE);
        break;
    }
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingSerial *setting = NM_SETTING_SERIAL(object);

    switch (prop_id) {
    case PROP_PARITY:
        g_value_set_enum(value, nm_setting_serial_get_parity(setting));
        break;
    default:
        _nm_setting_property_get_property_direct(object, prop_id, value, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingSerialPrivate *priv = NM_SETTING_SERIAL_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_PARITY:
        priv->parity = g_value_get_enum(value);
        break;
    default:
        _nm_setting_property_set_property_direct(object, prop_id, value, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_serial_init(NMSettingSerial *self)
{
    NMSettingSerialPrivate *priv = NM_SETTING_SERIAL_GET_PRIVATE(self);

    nm_assert(priv->parity == NM_SETTING_SERIAL_PARITY_NONE);
}

/**
 * nm_setting_serial_new:
 *
 * Creates a new #NMSettingSerial object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingSerial object
 **/
NMSetting *
nm_setting_serial_new(void)
{
    return g_object_new(NM_TYPE_SETTING_SERIAL, NULL);
}

static void
nm_setting_serial_class_init(NMSettingSerialClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingSerialPrivate));

    object_class->get_property = get_property;
    object_class->set_property = set_property;

    /**
     * NMSettingSerial:baud:
     *
     * Speed to use for communication over the serial port.  Note that this
     * value usually has no effect for mobile broadband modems as they generally
     * ignore speed settings and use the highest available speed.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_SERIAL_BAUD,
                                              PROP_BAUD,
                                              0,
                                              G_MAXUINT32,
                                              57600,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingSerialPrivate,
                                              baud);

    /**
     * NMSettingSerial:bits:
     *
     * Byte-width of the serial communication. The 8 in "8n1" for example.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_SERIAL_BITS,
                                              PROP_BITS,
                                              5,
                                              8,
                                              8,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingSerialPrivate,
                                              bits);

    /**
     * NMSettingSerial:parity:
     *
     * Parity setting of the serial port.
     **/
    /* ---keyfile---
     * property: parity
     * format: 'e', 'o', or 'n'
     * description: The connection parity; even, odd, or none. Note that older
     *   versions of NetworkManager stored this as an integer: 69 ('E') for even,
     *   111 ('o') for odd, or 110 ('n') for none.
     * example: parity=n
     * ---end---
     */
    /* ---dbus---
     * property: parity
     * format: byte
     * description: The connection parity: 69 (ASCII 'E') for even parity,
     *   111 (ASCII 'o') for odd, 110 (ASCII 'n') for none.
     * ---end---
     */
    obj_properties[PROP_PARITY] = g_param_spec_enum(NM_SETTING_SERIAL_PARITY,
                                                    "",
                                                    "",
                                                    NM_TYPE_SETTING_SERIAL_PARITY,
                                                    NM_SETTING_SERIAL_PARITY_NONE,
                                                    G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(
        properties_override,
        obj_properties[PROP_PARITY],
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_BYTE,
                                       .compare_fcn = _nm_setting_property_compare_fcn_default,
                                       .to_dbus_fcn = parity_to_dbus_fcn,
                                       .typdata_from_dbus.gprop_fcn = parity_from_dbus,
                                       .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_gprop,
                                       .from_dbus_is_full = TRUE));

    /**
     * NMSettingSerial:stopbits:
     *
     * Number of stop bits for communication on the serial port.  Either 1 or 2.
     * The 1 in "8n1" for example.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_SERIAL_STOPBITS,
                                              PROP_STOPBITS,
                                              1,
                                              2,
                                              1,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingSerialPrivate,
                                              stopbits);

    /**
     * NMSettingSerial:send-delay:
     *
     * Time to delay between each byte sent to the modem, in microseconds.
     **/
    _nm_setting_property_define_direct_uint64(properties_override,
                                              obj_properties,
                                              NM_SETTING_SERIAL_SEND_DELAY,
                                              PROP_SEND_DELAY,
                                              0,
                                              G_MAXUINT64,
                                              0,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingSerialPrivate,
                                              send_delay);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_SERIAL,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
