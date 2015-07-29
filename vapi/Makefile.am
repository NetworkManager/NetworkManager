EXTRA_DIST = \
	NetworkManager-1.0.metadata \
	NMClient-1.0.metadata \
	libnm-util.deps \
	libnm-glib.deps

if WITH_LEGACY_LIBRARIES
VAPIGEN_VAPIS = libnm-util.vapi libnm-glib.vapi
endif

if ENABLE_VAPIGEN
include Makefile.vapigen

libnm-util.vapi: $(top_builddir)/libnm-util/NetworkManager-1.0.gir  libnm-util.deps NetworkManager-1.0.metadata
libnm-glib.vapi: $(top_builddir)/libnm-glib/NMClient-1.0.gir  libnm-glib.deps NMClient-1.0.metadata libnm-util.vapi


libnm_util_vapi_METADATADIRS = $(srcdir)
libnm_util_vapi_FILES = $(top_builddir)/libnm-util/NetworkManager-1.0.gir

libnm_glib_vapi_METADATADIRS = $(srcdir)
libnm_glib_vapi_FILES = $(top_builddir)/libnm-glib/NMClient-1.0.gir
libnm_glib_vapi_VAPIDIRS = $(builddir)
libnm_glib_vapi_GIRDIRS = $(top_builddir)/libnm-util
libnm_glib_vapi_DEPS = gio-2.0

vapidir = $(datadir)/vala/vapi
vapi_DATA = $(VAPIGEN_VAPIS) $(VAPIGEN_VAPIS:.vapi=.deps)

endif

CLEANFILES = $(VAPIGEN_VAPIS)
