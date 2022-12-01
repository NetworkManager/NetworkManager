/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */
/**
 * SECTION:nmt-8021x-fields
 * @short_description: Widgets for 802.1X setting
 *
 * #Nmt8021xFields provides widgets to configure the 802.1X setting
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-8021x-fields.h"
#include "nmt-editor-grid.h"
#include "nmt-password-fields.h"
#include "nm-editor-bindings.h"

typedef struct _EapMethod EapMethod;

typedef struct {
    const char *id;
    const char *label;
    gboolean    only_for_wired;
    void (*populate)(EapMethod *method, NmtNewtWidget *grid);
    void (*selected)(EapMethod *method);
} EapMethodDesc;

struct _EapMethod {
    const EapMethodDesc *desc;
    NMSetting8021x      *setting;
    NmtNewtWidget       *inner_popup;
};

typedef struct {
    NMSetting8021x *setting;
    NmtNewtWidget  *authentication;
    NmtNewtWidget  *phase2_auth;
    gboolean        is_wired;
    gboolean        is_updating;
    EapMethod      *eap_methods;
} Nmt8021xFieldsPrivate;

struct _Nmt8021xFields {
    NmtNewtGrid           parent;
    Nmt8021xFieldsPrivate _priv;
};

struct _Nmt8021xFieldsClass {
    NmtNewtGridClass parent;
};

G_DEFINE_TYPE(Nmt8021xFields, nmt_8021x_fields, NMT_TYPE_EDITOR_GRID)

#define NMT_8021X_FIELDS_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, Nmt8021xFields, NMT_IS_8021X_FIELDS)

enum {
    PROP_0,
    PROP_IS_WIRED,
    PROP_SETTING,

    LAST_PROP
};

static void
nmt_8021x_fields_init(Nmt8021xFields *fields)
{}

/**
 * nmt_8021x_fields_new:
 * @setting: the backing 802.1X setting
 * @is_wired: whether the setting is for a wired connection or wireless
 *
 * Creates a new #Nmt8021xFields
 *
 * Returns: a new #Nmt8021xFields
 */
NmtNewtWidget *
nmt_8021x_fields_new(NMSetting8021x *setting, gboolean is_wired)
{
    return g_object_new(NMT_TYPE_8021X_FIELDS, "setting", setting, "is-wired", is_wired, NULL);
}

static gboolean
eap_methods_to_string(GBinding     *binding,
                      const GValue *source_value,
                      GValue       *target_value,
                      gpointer      user_data)
{
    char **strv;

    strv = g_value_get_boxed(source_value);
    if (!strv)
        return FALSE;

    /* The API allows multiple EAP methods. The UI to
     * support this would be complicate, only allow
     * one for now. */
    g_value_set_string(target_value, strv[0]);
    return TRUE;
}

static gboolean
eap_methods_from_string(GBinding     *binding,
                        const GValue *source_value,
                        GValue       *target_value,
                        gpointer      user_data)
{
    const char *text;
    char      **strv = g_new(char *, 2);

    text    = g_value_get_string(source_value);
    strv[0] = g_strdup(text);
    strv[1] = NULL;

    g_value_take_boxed(target_value, strv);
    return TRUE;
}

static gboolean
cert_validate(NmtNewtEntry *entry, const char *text, gpointer user_data)
{
    NMSetting8021xCKScheme scheme;

    scheme = nm_setting_802_1x_check_cert_scheme(text, strlen(text) + 1, NULL);
    return scheme != NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
}

static void
phase2_auth_widget_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    NmtNewtWidget  *widget  = NMT_NEWT_WIDGET(object);
    NMSetting8021x *setting = user_data;
    const char     *active_id;
    const char     *auth_eap;
    const char     *auth;

    active_id = nmt_newt_popup_get_active_id(NMT_NEWT_POPUP(widget));

    if (g_str_has_prefix(active_id, "eap-")) {
        auth_eap = &active_id[NM_STRLEN("eap-")];
        auth     = NULL;
    } else {
        auth_eap = NULL;
        auth     = active_id;
    }

    if (!nm_streq0(auth, nm_setting_802_1x_get_phase2_auth(setting)))
        g_object_set(setting, NM_SETTING_802_1X_PHASE2_AUTH, auth, NULL);
    if (!nm_streq0(auth_eap, nm_setting_802_1x_get_phase2_autheap(setting)))
        g_object_set(setting, NM_SETTING_802_1X_PHASE2_AUTHEAP, auth_eap, NULL);
}

static void
phase2_auth_setting_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    NMSetting8021x *setting   = NM_SETTING_802_1X(object);
    NmtNewtWidget  *widget    = user_data;
    gs_free char   *active_id = NULL;
    const char     *auth;

    auth = nm_setting_802_1x_get_phase2_auth(setting);
    if (auth) {
        active_id = g_strdup(auth);
    } else {
        auth = nm_setting_802_1x_get_phase2_autheap(setting);
        if (auth)
            active_id = g_strdup_printf("eap-%s", auth);
    }

    if (active_id)
        nmt_newt_popup_set_active_id(NMT_NEWT_POPUP(widget), active_id);
}

static void
eap_method_populate_simple(EapMethod *method, NmtNewtWidget *subgrid)
{
    NmtNewtWidget *widget;

    widget = nmt_newt_entry_new(40, NMT_NEWT_ENTRY_NONEMPTY);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Username"), widget, NULL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_IDENTITY,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_password_fields_new(40, NMT_PASSWORD_FIELDS_SHOW_PASSWORD);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_PASSWORD,
                           widget,
                           "password",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Password"), widget, NULL);
}

static void
eap_method_populate_tls(EapMethod *method, NmtNewtWidget *subgrid)
{
    NmtNewtWidget *widget;

    widget = nmt_newt_entry_new(40, NMT_NEWT_ENTRY_NONEMPTY);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Identity"), widget, NULL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_IDENTITY,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Domain"), widget, NULL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_DOMAIN_SUFFIX_MATCH,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("CA cert"), widget, NULL);
    nmt_newt_entry_set_validator(NMT_NEWT_ENTRY(widget), cert_validate, NULL);
    g_object_bind_property_full(method->setting,
                                NM_SETTING_802_1X_CA_CERT,
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                certificate_to_string,
                                certificate_from_string,
                                NULL,
                                NULL);

    widget =
        nmt_password_fields_new(40,
                                NMT_PASSWORD_FIELDS_SHOW_PASSWORD | NMT_PASSWORD_FIELDS_NOT_EMPTY);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_CA_CERT_PASSWORD,
                           widget,
                           "password",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("CA cert password"), widget, NULL);

    widget = nmt_newt_entry_new(40, NMT_NEWT_ENTRY_NONEMPTY);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("User cert"), widget, NULL);
    nmt_newt_entry_set_validator(NMT_NEWT_ENTRY(widget), cert_validate, NULL);
    g_object_bind_property_full(method->setting,
                                NM_SETTING_802_1X_CLIENT_CERT,
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                certificate_to_string,
                                certificate_from_string,
                                NULL,
                                NULL);

    widget =
        nmt_password_fields_new(40,
                                NMT_PASSWORD_FIELDS_SHOW_PASSWORD | NMT_PASSWORD_FIELDS_NOT_EMPTY);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_CLIENT_CERT_PASSWORD,
                           widget,
                           "password",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("User cert password"), widget, NULL);

    widget = nmt_newt_entry_new(40, NMT_NEWT_ENTRY_NONEMPTY);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("User private key"), widget, NULL);
    nmt_newt_entry_set_validator(NMT_NEWT_ENTRY(widget), cert_validate, NULL);
    g_object_bind_property_full(method->setting,
                                NM_SETTING_802_1X_PRIVATE_KEY,
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                certificate_to_string,
                                certificate_from_string,
                                NULL,
                                NULL);

    widget = nmt_password_fields_new(40, NMT_PASSWORD_FIELDS_SHOW_PASSWORD);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD,
                           widget,
                           "password",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("User privkey password"), widget, NULL);
}

static void
eap_method_populate_ttls(EapMethod *method, NmtNewtWidget *subgrid)
{
    NmtNewtWidget    *widget;
    NmtNewtPopupEntry ttls_inner_methods[] = {{N_("PAP"), "pap"},
                                              {N_("MSCHAP"), "mschap"},
                                              {N_("MSCHAPv2"), "eap-mschapv2"},
                                              {N_("MSCHAPv2 (no EAP)"), "mschapv2"},
                                              {N_("CHAP"), "chap"},
                                              {N_("MD5"), "eap-md5"},
                                              {N_("GTC"), "eap-gtc"},
                                              {NULL, NULL}};

    widget = nmt_newt_entry_new(40, NMT_NEWT_ENTRY_NONEMPTY);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Anonymous identity"), widget, NULL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_ANONYMOUS_IDENTITY,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("CA cert"), widget, NULL);
    nmt_newt_entry_set_validator(NMT_NEWT_ENTRY(widget), cert_validate, NULL);
    g_object_bind_property_full(method->setting,
                                NM_SETTING_802_1X_CA_CERT,
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                certificate_to_string,
                                certificate_from_string,
                                NULL,
                                NULL);

    widget =
        nmt_password_fields_new(40,
                                NMT_PASSWORD_FIELDS_SHOW_PASSWORD | NMT_PASSWORD_FIELDS_NOT_EMPTY);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_CA_CERT_PASSWORD,
                           widget,
                           "password",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("CA cert password"), widget, NULL);

    widget              = nmt_newt_popup_new(ttls_inner_methods);
    method->inner_popup = widget;
    g_signal_connect(widget,
                     "notify::active-id",
                     G_CALLBACK(phase2_auth_widget_changed),
                     method->setting);
    g_signal_connect(method->setting,
                     "notify::" NM_SETTING_802_1X_PHASE2_AUTH,
                     G_CALLBACK(phase2_auth_setting_changed),
                     widget);
    g_signal_connect(method->setting,
                     "notify::" NM_SETTING_802_1X_PHASE2_AUTHEAP,
                     G_CALLBACK(phase2_auth_setting_changed),
                     widget);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Inner authentication"), widget, NULL);

    if (nm_setting_802_1x_get_num_eap_methods(method->setting) > 0
        && nm_streq0(nm_setting_802_1x_get_eap_method(method->setting, 0), "ttls")) {
        phase2_auth_setting_changed(G_OBJECT(method->setting), NULL, widget);
    }

    widget = nmt_newt_entry_new(40, NMT_NEWT_ENTRY_NONEMPTY);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Username"), widget, NULL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_IDENTITY,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_password_fields_new(40,
                                     NMT_PASSWORD_FIELDS_SHOW_PASSWORD
                                         | NMT_PASSWORD_FIELDS_SHOW_SECRET_FLAGS);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_PASSWORD,
                           widget,
                           "password",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_PASSWORD_FLAGS,
                           widget,
                           "secret-flags",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Password"), widget, NULL);
}

static void
eap_method_populate_peap(EapMethod *method, NmtNewtWidget *subgrid)
{
    NmtNewtWidget           *widget;
    static NmtNewtPopupEntry peap_version_entries[] = {{N_("Automatic"), NULL},
                                                       {N_("Version 0"), "0"},
                                                       {N_("Version 1"), "1"},
                                                       {NULL, NULL}};
    static NmtNewtPopupEntry peap_inner_methods[]   = {{N_("MSCHAPv2"), "mschapv2"},
                                                       {N_("MD5"), "md5"},
                                                       {N_("GTC"), "gtc"},
                                                       {NULL, NULL}};

    widget = nmt_newt_entry_new(40, NMT_NEWT_ENTRY_NONEMPTY);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Anonymous identity"), widget, NULL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_ANONYMOUS_IDENTITY,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Domain"), widget, NULL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_DOMAIN_SUFFIX_MATCH,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_newt_entry_new(40, 0);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("CA cert"), widget, NULL);
    nmt_newt_entry_set_validator(NMT_NEWT_ENTRY(widget), cert_validate, NULL);
    g_object_bind_property_full(method->setting,
                                NM_SETTING_802_1X_CA_CERT,
                                widget,
                                "text",
                                G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL,
                                certificate_to_string,
                                certificate_from_string,
                                NULL,
                                NULL);

    widget =
        nmt_password_fields_new(40,
                                NMT_PASSWORD_FIELDS_SHOW_PASSWORD | NMT_PASSWORD_FIELDS_NOT_EMPTY);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_CA_CERT_PASSWORD,
                           widget,
                           "password",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("CA cert password"), widget, NULL);

    widget = nmt_newt_popup_new(peap_version_entries);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_PHASE1_PEAPVER,
                           widget,
                           "active-id",
                           G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("PEAP version"), widget, NULL);

    widget              = nmt_newt_popup_new(peap_inner_methods);
    method->inner_popup = widget;
    g_signal_connect(widget,
                     "notify::active-id",
                     G_CALLBACK(phase2_auth_widget_changed),
                     method->setting);
    g_signal_connect(method->setting,
                     "notify::" NM_SETTING_802_1X_PHASE2_AUTH,
                     G_CALLBACK(phase2_auth_setting_changed),
                     widget);
    g_signal_connect(method->setting,
                     "notify::" NM_SETTING_802_1X_PHASE2_AUTHEAP,
                     G_CALLBACK(phase2_auth_setting_changed),
                     widget);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Inner authentication"), widget, NULL);

    if (nm_setting_802_1x_get_num_eap_methods(method->setting) > 0
        && nm_streq0(nm_setting_802_1x_get_eap_method(method->setting, 0), "peap")) {
        phase2_auth_setting_changed(G_OBJECT(method->setting), NULL, widget);
    }

    widget = nmt_newt_entry_new(40, NMT_NEWT_ENTRY_NONEMPTY);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Username"), widget, NULL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_IDENTITY,
                           widget,
                           "text",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

    widget = nmt_password_fields_new(40,
                                     NMT_PASSWORD_FIELDS_SHOW_PASSWORD
                                         | NMT_PASSWORD_FIELDS_SHOW_SECRET_FLAGS);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_PASSWORD,
                           widget,
                           "password",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    g_object_bind_property(method->setting,
                           NM_SETTING_802_1X_PASSWORD_FLAGS,
                           widget,
                           "secret-flags",
                           G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
    nmt_editor_grid_append(NMT_EDITOR_GRID(subgrid), _("Password"), widget, NULL);
}

static void
eap_method_selected_tunneled(EapMethod *method)
{
    phase2_auth_widget_changed(G_OBJECT(method->inner_popup), NULL, method->setting);
}

static const EapMethodDesc eap_method_descs[] = {
    {
        .id             = "md5",
        .label          = N_("MD5"),
        .only_for_wired = TRUE,
        .populate       = eap_method_populate_simple,
    },
    {
        .id       = "pwd",
        .label    = N_("PWD"),
        .populate = eap_method_populate_simple,
    },
    {
        .id       = "tls",
        .label    = N_("TLS"),
        .populate = eap_method_populate_tls,
    },
    {
        .id       = "ttls",
        .label    = N_("TTLS"),
        .populate = eap_method_populate_ttls,
        .selected = eap_method_selected_tunneled,
    },
    {
        .id       = "peap",
        .label    = N_("PEAP"),
        .populate = eap_method_populate_peap,
        .selected = eap_method_selected_tunneled,
    },
    {},
};

static void
eap_method_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    Nmt8021xFields        *self = user_data;
    Nmt8021xFieldsPrivate *priv = NMT_8021X_FIELDS_GET_PRIVATE(self);
    int                    active;

    active = nmt_newt_popup_get_active(NMT_NEWT_POPUP(priv->authentication));
    if (priv->eap_methods[active].desc->selected)
        priv->eap_methods[active].desc->selected(&priv->eap_methods[active]);
}

static void
nmt_8021x_fields_constructed(GObject *object)
{
    Nmt8021xFields        *self    = NMT_8021X_FIELDS(object);
    Nmt8021xFieldsPrivate *priv    = NMT_8021X_FIELDS_GET_PRIVATE(self);
    NmtEditorGrid         *grid    = NMT_EDITOR_GRID(object);
    gs_unref_array GArray *entries = NULL;
    NmtNewtStack          *stack;
    NmtNewtWidget         *subgrid;
    NmtNewtWidget         *widget;
    guint                  i, j;
    EapMethod             *method;

    /* Create the EAP methods popup */
    entries = g_array_new(TRUE, TRUE, sizeof(NmtNewtPopupEntry));
    for (i = 0; eap_method_descs[i].id; i++) {
        NmtNewtPopupEntry entry;

        if (eap_method_descs[i].only_for_wired && !priv->is_wired)
            continue;

        entry.label = (char *) eap_method_descs[i].label;
        entry.id    = (char *) eap_method_descs[i].id;
        g_array_append_val(entries, entry);
    }
    priv->authentication = nmt_newt_popup_new(nm_g_array_index_p(entries, NmtNewtPopupEntry, 0));
    nmt_editor_grid_append(grid, "Authentication", NMT_NEWT_WIDGET(priv->authentication), NULL);

    widget = nmt_newt_stack_new();
    stack  = NMT_NEWT_STACK(widget);

    /* Instantiate EAP methods and populate widgets */
    priv->eap_methods = g_new0(EapMethod, G_N_ELEMENTS(eap_method_descs));
    for (i = 0, j = 0; eap_method_descs[i].id; i++) {
        if (eap_method_descs[i].only_for_wired && !priv->is_wired)
            continue;

        method          = &priv->eap_methods[j++];
        method->desc    = &eap_method_descs[i];
        method->setting = priv->setting;

        subgrid = nmt_editor_grid_new();
        method->desc->populate(method, subgrid);
        nmt_newt_stack_add(stack, method->desc->id, subgrid);
    }

    g_object_bind_property(priv->authentication,
                           "active-id",
                           stack,
                           "active-id",
                           G_BINDING_SYNC_CREATE);
    g_object_bind_property_full(priv->setting,
                                NM_SETTING_802_1X_EAP,
                                priv->authentication,
                                "active-id",
                                G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE,
                                eap_methods_to_string,
                                eap_methods_from_string,
                                NULL,
                                NULL);

    /* When the popup value changes, in addition to updating the stack and the setting,
     * we need to refresh the selected EAP method's widget to ensure the setting and
     * the widget are in sync. */
    g_signal_connect(priv->authentication,
                     "notify::active-id",
                     G_CALLBACK(eap_method_changed),
                     self);

    nmt_editor_grid_append(grid, NULL, NMT_NEWT_WIDGET(stack), NULL);

    G_OBJECT_CLASS(nmt_8021x_fields_parent_class)->constructed(object);
}

static void
nmt_8021x_fields_finalize(GObject *object)
{
    Nmt8021xFields        *self = NMT_8021X_FIELDS(object);
    Nmt8021xFieldsPrivate *priv = NMT_8021X_FIELDS_GET_PRIVATE(self);

    nm_clear_g_free(&priv->eap_methods);
    g_clear_object(&priv->authentication);

    G_OBJECT_CLASS(nmt_8021x_fields_parent_class)->finalize(object);
}

static void
nmt_8021x_fields_set_property(GObject      *object,
                              guint         prop_id,
                              const GValue *value,
                              GParamSpec   *pspec)
{
    Nmt8021xFields        *self = NMT_8021X_FIELDS(object);
    Nmt8021xFieldsPrivate *priv = NMT_8021X_FIELDS_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_SETTING:
        priv->setting = g_object_ref(g_value_get_object(value));
        break;
    case PROP_IS_WIRED:
        priv->is_wired = g_value_get_boolean(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nmt_8021x_fields_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    Nmt8021xFields        *self = NMT_8021X_FIELDS(object);
    Nmt8021xFieldsPrivate *priv = NMT_8021X_FIELDS_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_SETTING:
        g_value_set_object(value, priv->setting);
        break;
    case PROP_IS_WIRED:
        g_value_set_boolean(value, priv->is_wired);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nmt_8021x_fields_class_init(Nmt8021xFieldsClass *entry_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(entry_class);

    object_class->constructed  = nmt_8021x_fields_constructed;
    object_class->finalize     = nmt_8021x_fields_finalize;
    object_class->set_property = nmt_8021x_fields_set_property;
    object_class->get_property = nmt_8021x_fields_get_property;

    /**
     * Nmt8021xFields:setting:
     *
     * The backing 802.1X setting
     */
    g_object_class_install_property(
        object_class,
        PROP_SETTING,
        g_param_spec_object("setting",
                            "",
                            "",
                            NM_TYPE_SETTING_802_1X,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
    /**
     * Nmt8021xFields:is-wired
     *
     * Whether the setting is for a wired connection
     */
    g_object_class_install_property(
        object_class,
        PROP_IS_WIRED,
        g_param_spec_boolean("is-wired",
                             "",
                             "",
                             FALSE,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}
