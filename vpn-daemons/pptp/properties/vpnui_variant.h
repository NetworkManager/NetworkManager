#ifndef NMVPNUI_VARIANT_H
#define NMVPNUI_VARIANT_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#include <gtk/gtk.h>
#include <string.h>
#include <glade/glade.h>

#include "vpnui_impl.h"

typedef struct VpnUIVariant
{
  char   *name;
  char   *description;
  GSList   *defaults;
  NetworkManagerVpnUIImpl *impl;
} VpnUIVariant;

#define STORAGE_CLASS extern
#ifdef NMVPNUI_EXPAND_C
#undef STORAGE_CLASS 
#define STORAGE_CLASS 
#endif

STORAGE_CLASS void vpnui_variant_free( VpnUIVariant *variant );
STORAGE_CLASS VpnUIVariant *vpnui_variant_new( const char *name,
                                      const char *description,
                                      const char *defaults,
                                      NetworkManagerVpnUIImpl *impl
                                    );
STORAGE_CLASS VpnUIVariant *vpnui_variant_byname (NetworkManagerVpnUIImpl *impl, const char *name);
STORAGE_CLASS void vpnui_variant_select (VpnUIVariant *variant);
STORAGE_CLASS void vpnui_variant_select_byname (NetworkManagerVpnUIImpl *impl, const char *name);
#undef STORAGE_CLASS
#endif
