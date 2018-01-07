# FIXME: nmcli-completion should be renamed to nmcli
install_data(
  'nmcli-completion',
  install_dir: join_paths(nm_datadir, 'bash-completion', 'completions')
)

sources = files(
  'agent.c',
  'common.c',
  'connections.c',
  'devices.c',
  'general.c',
  'nmcli.c',
  'polkit-agent.c',
  'settings.c',
  'utils.c'
)

deps = [
  libnm_dep,
  libnmc_base_dep,
  libnmc_dep,
  nm_core_dep,
  readline_dep
]

cflags = clients_cflags + [
  '-DG_LOG_DOMAIN="nmcli"',
  '-DNMCLI_LOCALEDIR="@0@"'.format(nm_localedir)
]

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(linker_script_binary)
endif

if enable_polkit_agent
  sources += nm_polkit_listener

  deps += polkit_agent_dep
endif

executable(
  'nmcli',
  sources,
  dependencies: deps,
  c_args: cflags,
  link_args: ldflags,
  link_depends: linker_script_binary,
  install: true
)
