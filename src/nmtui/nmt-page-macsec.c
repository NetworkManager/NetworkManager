/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */
/**
 * SECTION:nmt-page-macsec
 * @short_description: The editor page for MACsec connections
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-page-macsec.h"

#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "nmt-device-entry.h"
#include "nmt-password-fields.h"
#include "nmt-8021x-fields.h"

typedef struct {
    NMSetting8021x *s_8021x;
} NmtPageMacsecPrivate;

struct _NmtPageMacsec {
    NmtEditorPageDevice  parent;
    NmtPageMacsecPrivate _priv;
};

struct _NmtPageMacsecClass {
    NmtEditorPageDeviceClass parent;
};

G_DEFINE_TYPE(NmtPageMacsec, nmt_page_macsec, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_MACSEC_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NmtPageMacsec, NMT_IS_PAGE_MACSEC)

static void
nmt_page_macsec_init(NmtPageMacsec *macsec)
{}

NmtEditorPage *
nmt_page_macsec_new(NMConnection *conn, NmtDeviceEntry *deventry)
{
    return g_object_new(NMT_TYPE_PAGE_MACSEC, "connection", conn, "device-entry", deventry, NULL);
}

static void
macsec_mode_changed(NmtNewtWidget *widget, GParamSpec *pspec, gpointer user_data)
{
    NmtPageMacsec        *macsec = user_data;
    NmtPageMacsecPrivate *priv   = NMT_PAGE_MACSEC_GET_PRIVATE(macsec);
    NMConnection         *conn;
    gboolean              mode_eap;
    gboolean              has_setting;

    conn        = nmt_editor_page_get_connection(NMT_EDITOR_PAGE(macsec));
    has_setting = !!nm_connection_get_setting(conn, NM_TYPE_SETTING_802_1X);
    mode_eap    = nmt_newt_popup_get_active(NMT_NEWT_POPUP(widget)) == NM_SETTING_MACSEC_MODE_EAP;

    if (mode_eap != has_setting) {
        if (mode_eap)
            nm_connection_add_setting(conn, NM_SETTING(priv->s_8021x));
        else
            nm_connection_remove_setting(conn, NM_TYPE_SETTING_802_1X);
    }
}

static NmtNewtPopupEntry macsec_mode[] = {{N_("PSK"), "psk"}, {N_("EAP"), "eap"}, {NULL, NULL}};

static NmtNewtPopupEntry macsec_validation[] = {{N_("Disabled"), "disabled"},
                                                {N_("Check"), "check"},
                                                {N_("Strict"), "strict"},
                                                {NULL, NULL}};

static void
nmt_page_macsec_constructed(GObject *object)
{
    NmtPageMacsec        *macsec = NMT_PAGE_MACSEC(object);
    NmtPageMacsecPrivate *priv   = NMT_PAGE_MACSEC_GET_PRIVATE(macsec);
    NMConnection         *conn;
    NMSettingMacsec      *s_macsec;
    NMSetting8021x       *s_8021x;
    NmtNewtStack         *stack;
    NmtEditorSection     *section;
    NmtEditorGrid        *grid;
    NmtNewtWidget        *subgrid;
    NmtNewtWidget        *widget;
    NmtNewtWidget        *mode;

    conn     = nmt_editor_page_get_connection(NMT_EDITOR_PAGE(macsec));
    s_macsec = _nm_connection_ensure_setting(conn, NM_TYPE_SETTING_MACSEC);

    s_8021x = nm_connection_get_setting_802_1x(conn);
    if (!s_8021x) {
        s_8021x = NM_SETTING_802_1X(nm_setting_802_1x_new());
        nm_setting_802_1x_add_eap_method(s_8021x, "MD5");
    }
    priv->s_8021x = g_object_ref(s_8021x);

    section = nmt_editor_section_new(_("MACsec"), NULL, TRUE);
    grid    = nmt_editor_section_get_body(section);

    widget = nmt_device_entry_new(_("Parent device"), 40, G_TYPE_NONE);
    g_object_bind_property(s_macsec,
                           NM_SETTING_MACSEC_PARENT,
                           widget,
                           "interface-name",
                           G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
    nmt_editor_grid_append(grid, NULL, widget, NULL);

    nmt_editor_grid_append(grid, NULL, nmt_newt_separator_new(), NULL);

    widget = nmt_newt_popup_new((NmtNewtPopupEntry *) &macsec_mode);
    nmt_editor_grid_append(grid, _("Mode"), widget, NULL);
    mode = widget;

    widget = nmt_newt_stack_new();
    stack  = NMT_NEWT_STACK(widget);

    /* PSK stack grid */
    subgrid = nmt_editor_grid_new();
    widget =
        nmt_password_fields_new(40,
                                NMT_PASSWORD_FIELDS_SHOW_PASSWORD | NMT_PASSWORD_FIELDS_NOT_EMPTY);
    g_object_bind_property(s_macsec,
                           NM_SETTING_MACSEC_MKA_CAK,
                           widget,
                           "password",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("CAK"), widget, NULL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("CKN"), widget, NULL);
    g_object_bind_property(s_macsec,
                           NM_SETTING_MACSEC_MKA_CKN,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    nmt_newt_stack_add(stack, "psk", subgrid);

    /* EAP stack grid */
    subgrid = nmt_editor_grid_new();
    widget  = NMT_NEWT_WIDGET(nmt_8021x_fields_new(s_8021x, TRUE));
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), NULL, widget, NULL);
    nmt_newt_stack_add(stack, "eap", subgrid);

    g_object_bind_property(mode, "active-id", stack, "active-id", G_BINDING_SYNC_CREATE);
    nmt_editor_grid_append(grid, NULL, NMT_NEWT_WIDGET(stack), NULL);

    g_object_bind_property(s_macsec,
                           NM_SETTING_MACSEC_MODE,
                           mode,
                           "active",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    g_signal_connect(mode, "notify::active", G_CALLBACK(macsec_mode_changed), macsec);
    macsec_mode_changed(mode, NULL, macsec);

    nmt_editor_grid_append(grid, NULL, nmt_newt_separator_new(), NULL);

    /* Other MACsec options */
    widget = nmt_newt_popup_new((NmtNewtPopupEntry *) &macsec_validation);
    nmt_editor_grid_append(grid, _("Validation"), widget, NULL);
    g_object_bind_property(s_macsec,
                           NM_SETTING_MACSEC_VALIDATION,
                           widget,
                           "active",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(grid, _("SCI port"), widget, NULL);
    g_object_bind_property(s_macsec,
                           NM_SETTING_MACSEC_PORT,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_checkbox_new(_("Encrypt traffic"));
    nmt_editor_grid_append(grid, NULL, widget, NULL);
    g_object_bind_property(s_macsec,
                           NM_SETTING_MACSEC_ENCRYPT,
                           widget,
                           "active",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    nmt_editor_page_add_section(NMT_EDITOR_PAGE(macsec), section);

    G_OBJECT_CLASS(nmt_page_macsec_parent_class)->constructed(object);
}

static void
nmt_page_macsec_class_init(NmtPageMacsecClass *macsec_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(macsec_class);

    object_class->constructed = nmt_page_macsec_constructed;
}
