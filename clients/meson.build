name = 'nm-online'

incs = [
  top_inc,
  shared_inc,
  libnm_core_inc
]

deps = [
  glib_dep,
  libnm_dep
]

cflags = [
  '-DG_LOG_DOMAIN="@0@"'.format(name),
  '-DNMLOCALEDIR="@0@"'.format(nm_localedir)
]

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(linker_script_binary)
endif

executable(
  name,
  [name + '.c', libnm_core_enum[1]],
  include_directories: incs,
  dependencies: deps,
  c_args: cflags,
  link_args: ldflags,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_bindir
)

subdir('common')

if enable_nmcli
  subdir('cli')
endif

if enable_nmtui
  subdir('tui')
endif
