/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ppp.h"

#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ppp
 * @short_description: Describes connection properties for devices/networks
 * that require PPP to deliver IP capability
 *
 * The #NMSettingPpp object is a #NMSetting subclass that describes properties
 * necessary for connection to networks that require PPP transport, like PPPoE
 * cable and DSL modems and some mobile broadband devices.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_NOAUTH,
                                  PROP_REFUSE_EAP,
                                  PROP_REFUSE_PAP,
                                  PROP_REFUSE_CHAP,
                                  PROP_REFUSE_MSCHAP,
                                  PROP_REFUSE_MSCHAPV2,
                                  PROP_NOBSDCOMP,
                                  PROP_NODEFLATE,
                                  PROP_NO_VJ_COMP,
                                  PROP_REQUIRE_MPPE,
                                  PROP_REQUIRE_MPPE_128,
                                  PROP_MPPE_STATEFUL,
                                  PROP_CRTSCTS,
                                  PROP_BAUD,
                                  PROP_MRU,
                                  PROP_MTU,
                                  PROP_LCP_ECHO_FAILURE,
                                  PROP_LCP_ECHO_INTERVAL, );

typedef struct {
    guint32 baud;
    guint32 mru;
    guint32 mtu;
    guint32 lcp_echo_failure;
    guint32 lcp_echo_interval;
    bool    noauth;
    bool    refuse_eap;
    bool    refuse_pap;
    bool    refuse_chap;
    bool    refuse_mschap;
    bool    refuse_mschapv2;
    bool    nobsdcomp;
    bool    nodeflate;
    bool    no_vj_comp;
    bool    require_mppe;
    bool    require_mppe_128;
    bool    mppe_stateful;
    bool    crtscts;
} NMSettingPppPrivate;

/**
 * NMSettingPpp:
 *
 * Point-to-Point Protocol Settings
 */
struct _NMSettingPpp {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingPppClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingPpp, nm_setting_ppp, NM_TYPE_SETTING)

#define NM_SETTING_PPP_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_PPP, NMSettingPppPrivate))

/*****************************************************************************/

/**
 * nm_setting_ppp_get_noauth:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:noauth property of the setting
 **/
gboolean
nm_setting_ppp_get_noauth(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->noauth;
}

/**
 * nm_setting_ppp_get_refuse_eap:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:refuse-eap property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_eap(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->refuse_eap;
}

/**
 * nm_setting_ppp_get_refuse_pap:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:refuse-pap property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_pap(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->refuse_pap;
}

/**
 * nm_setting_ppp_get_refuse_chap:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:refuse-chap property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_chap(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->refuse_chap;
}

/**
 * nm_setting_ppp_get_refuse_mschap:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:refuse-mschap property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_mschap(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->refuse_mschap;
}

/**
 * nm_setting_ppp_get_refuse_mschapv2:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:refuse-mschapv2 property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_mschapv2(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->refuse_mschapv2;
}

/**
 * nm_setting_ppp_get_nobsdcomp:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:nobsdcomp property of the setting
 **/
gboolean
nm_setting_ppp_get_nobsdcomp(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->nobsdcomp;
}

/**
 * nm_setting_ppp_get_nodeflate:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:nodeflate property of the setting
 **/
gboolean
nm_setting_ppp_get_nodeflate(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->nodeflate;
}

/**
 * nm_setting_ppp_get_no_vj_comp:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:no-vj-comp property of the setting
 **/
gboolean
nm_setting_ppp_get_no_vj_comp(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->no_vj_comp;
}

/**
 * nm_setting_ppp_get_require_mppe:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:require-mppe property of the setting
 **/
gboolean
nm_setting_ppp_get_require_mppe(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->require_mppe;
}

/**
 * nm_setting_ppp_get_require_mppe_128:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:require-mppe-128 property of the setting
 **/
gboolean
nm_setting_ppp_get_require_mppe_128(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->require_mppe_128;
}

/**
 * nm_setting_ppp_get_mppe_stateful:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:mppe-stateful property of the setting
 **/
gboolean
nm_setting_ppp_get_mppe_stateful(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->mppe_stateful;
}

/**
 * nm_setting_ppp_get_crtscts:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:crtscts property of the setting
 **/
gboolean
nm_setting_ppp_get_crtscts(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), FALSE);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->crtscts;
}

/**
 * nm_setting_ppp_get_baud:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:baud property of the setting
 **/
guint32
nm_setting_ppp_get_baud(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), 0);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->baud;
}

/**
 * nm_setting_ppp_get_mru:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:mru property of the setting
 **/
guint32
nm_setting_ppp_get_mru(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), 0);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->mru;
}

/**
 * nm_setting_ppp_get_mtu:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:mtu property of the setting
 **/
guint32
nm_setting_ppp_get_mtu(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), 0);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->mtu;
}

/**
 * nm_setting_ppp_get_lcp_echo_failure:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:lcp-echo-failure property of the setting
 **/
guint32
nm_setting_ppp_get_lcp_echo_failure(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), 0);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->lcp_echo_failure;
}

/**
 * nm_setting_ppp_get_lcp_echo_interval:
 * @setting: the #NMSettingPpp
 *
 * Returns: the #NMSettingPpp:lcp-echo-interval property of the setting
 **/
guint32
nm_setting_ppp_get_lcp_echo_interval(NMSettingPpp *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPP(setting), 0);

    return NM_SETTING_PPP_GET_PRIVATE(setting)->lcp_echo_interval;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingPppPrivate *priv = NM_SETTING_PPP_GET_PRIVATE(setting);

    /* FIXME: Do we even want this or can we just let pppd evaluate the options? */
    if (priv->mru > 0) {
        if (priv->mru < 128 || priv->mru > 16384) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%d' is out of valid range <128-16384>"),
                        priv->mru);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_PPP_SETTING_NAME, NM_SETTING_PPP_MRU);
            return FALSE;
        }
    }

    if (priv->lcp_echo_failure > 0) {
        /* lcp_echo_interval must also be non-zero */
        if (priv->lcp_echo_interval == 0) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("setting this property requires non-zero '%s' property"),
                        NM_SETTING_PPP_LCP_ECHO_INTERVAL);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_PPP_SETTING_NAME,
                           NM_SETTING_PPP_LCP_ECHO_FAILURE);
            return FALSE;
        }
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_ppp_init(NMSettingPpp *self)
{}

/**
 * nm_setting_ppp_new:
 *
 * Creates a new #NMSettingPpp object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingPpp object
 **/
NMSetting *
nm_setting_ppp_new(void)
{
    return g_object_new(NM_TYPE_SETTING_PPP, NULL);
}

static void
nm_setting_ppp_class_init(NMSettingPppClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingPppPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingPpp:noauth:
     *
     * If %TRUE, do not require the other side (usually the PPP server) to
     * authenticate itself to the client.  If %FALSE, require authentication
     * from the remote side.  In almost all cases, this should be %TRUE.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_NOAUTH,
                                               PROP_NOAUTH,
                                               TRUE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               noauth);

    /**
     * NMSettingPpp:refuse-eap:
     *
     * If %TRUE, the EAP authentication method will not be used.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_REFUSE_EAP,
                                               PROP_REFUSE_EAP,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               refuse_eap);

    /**
     * NMSettingPpp:refuse-pap:
     *
     * If %TRUE, the PAP authentication method will not be used.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_REFUSE_PAP,
                                               PROP_REFUSE_PAP,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               refuse_pap);

    /**
     * NMSettingPpp:refuse-chap:
     *
     * If %TRUE, the CHAP authentication method will not be used.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_REFUSE_CHAP,
                                               PROP_REFUSE_CHAP,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               refuse_chap);

    /**
     * NMSettingPpp:refuse-mschap:
     *
     * If %TRUE, the MSCHAP authentication method will not be used.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_REFUSE_MSCHAP,
                                               PROP_REFUSE_MSCHAP,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               refuse_mschap);

    /**
     * NMSettingPpp:refuse-mschapv2:
     *
     * If %TRUE, the MSCHAPv2 authentication method will not be used.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_REFUSE_MSCHAPV2,
                                               PROP_REFUSE_MSCHAPV2,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               refuse_mschapv2);

    /**
     * NMSettingPpp:nobsdcomp:
     *
     * If %TRUE, BSD compression will not be requested.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_NOBSDCOMP,
                                               PROP_NOBSDCOMP,
                                               FALSE,
                                               NM_SETTING_PARAM_FUZZY_IGNORE,
                                               NMSettingPppPrivate,
                                               nobsdcomp);

    /**
     * NMSettingPpp:nodeflate:
     *
     * If %TRUE, "deflate" compression will not be requested.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_NODEFLATE,
                                               PROP_NODEFLATE,
                                               FALSE,
                                               NM_SETTING_PARAM_FUZZY_IGNORE,
                                               NMSettingPppPrivate,
                                               nodeflate);

    /**
     * NMSettingPpp:no-vj-comp:
     *
     * If %TRUE, Van Jacobsen TCP header compression will not be requested.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_NO_VJ_COMP,
                                               PROP_NO_VJ_COMP,
                                               FALSE,
                                               NM_SETTING_PARAM_FUZZY_IGNORE,
                                               NMSettingPppPrivate,
                                               no_vj_comp);

    /**
     * NMSettingPpp:require-mppe:
     *
     * If %TRUE, MPPE (Microsoft Point-to-Point Encryption) will be required for
     * the PPP session.  If either 64-bit or 128-bit MPPE is not available the
     * session will fail.  Note that MPPE is not used on mobile broadband
     * connections.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_REQUIRE_MPPE,
                                               PROP_REQUIRE_MPPE,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               require_mppe);

    /**
     * NMSettingPpp:require-mppe-128:
     *
     * If %TRUE, 128-bit MPPE (Microsoft Point-to-Point Encryption) will be
     * required for the PPP session, and the "require-mppe" property must also
     * be set to %TRUE.  If 128-bit MPPE is not available the session will fail.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_REQUIRE_MPPE_128,
                                               PROP_REQUIRE_MPPE_128,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               require_mppe_128);

    /**
     * NMSettingPpp:mppe-stateful:
     *
     * If %TRUE, stateful MPPE is used.  See pppd documentation for more
     * information on stateful MPPE.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_MPPE_STATEFUL,
                                               PROP_MPPE_STATEFUL,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               mppe_stateful);

    /**
     * NMSettingPpp:crtscts:
     *
     * If %TRUE, specify that pppd should set the serial port to use hardware
     * flow control with RTS and CTS signals.  This value should normally be set
     * to %FALSE.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PPP_CRTSCTS,
                                               PROP_CRTSCTS,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingPppPrivate,
                                               crtscts);

    /**
     * NMSettingPpp:baud:
     *
     * If non-zero, instruct pppd to set the serial port to the specified
     * baudrate.  This value should normally be left as 0 to automatically
     * choose the speed.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_PPP_BAUD,
                                              PROP_BAUD,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingPppPrivate,
                                              baud);

    /**
     * NMSettingPpp:mru:
     *
     * If non-zero, instruct pppd to request that the peer send packets no
     * larger than the specified size.  If non-zero, the MRU should be between
     * 128 and 16384.
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_PPP_MRU,
                                              PROP_MRU,
                                              0,
                                              16384,
                                              0,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingPppPrivate,
                                              mru);

    /**
     * NMSettingPpp:mtu:
     *
     * If non-zero, instruct pppd to send packets no larger than the specified
     * size.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_PPP_MTU,
                                              PROP_MTU,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingPppPrivate,
                                              mtu);

    /**
     * NMSettingPpp:lcp-echo-failure:
     *
     * If non-zero, instruct pppd to presume the connection to the peer has
     * failed if the specified number of LCP echo-requests go unanswered by the
     * peer.  The "lcp-echo-interval" property must also be set to a non-zero
     * value if this property is used.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_PPP_LCP_ECHO_FAILURE,
                                              PROP_LCP_ECHO_FAILURE,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingPppPrivate,
                                              lcp_echo_failure);

    /**
     * NMSettingPpp:lcp-echo-interval:
     *
     * If non-zero, instruct pppd to send an LCP echo-request frame to the peer
     * every n seconds (where n is the specified value).  Note that some PPP
     * peers will respond to echo requests and some will not, and it is not
     * possible to autodetect this.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_PPP_LCP_ECHO_INTERVAL,
                                              PROP_LCP_ECHO_INTERVAL,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingPppPrivate,
                                              lcp_echo_interval);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_PPP,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
