#ifndef NMVPNUI_EXPAND_H
#define NMVPNUI_EXPAND_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#include <gtk/gtk.h>
#include <string.h>
#include <glade/glade.h>

#include <vpnui_impl.h>

typedef struct VpnUIExpander
{
  char   *glade_name;
  NetworkManagerVpnUIImpl *impl;
  GtkWidget  *widget;
} VpnUIExpander;

#define STORAGE_CLASS extern
#ifdef NMVPNUI_EXPAND_C
#undef STORAGE_CLASS 
#define STORAGE_CLASS 
#endif

STORAGE_CLASS void vpnui_expand_free(VpnUIExpander *expand);
STORAGE_CLASS VpnUIExpander *vpnui_expand_new( char *glade_name,  
                           NetworkManagerVpnUIImpl *impl );

STORAGE_CLASS void vpnui_expand_reset(VpnUIExpander *expand);
STORAGE_CLASS void vpnui_expand_reset_all (NetworkManagerVpnUIImpl *impl);

#undef STORAGE_CLASS
#endif
