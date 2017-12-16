examples = [
  ['add-connection-gdbus', [uuid_dep], [libnm_core_enum[1], libnm_enum[1]]],
  ['add-connection-libnm', [libnm_dep], []],
  ['get-active-connections-gdbus', [], [libnm_core_enum[1], libnm_enum[1]]],
  ['get-ap-info-libnm', [libnm_dep], []],
  ['list-connections-gdbus', [], []],
  ['list-connections-libnm', [libnm_dep], []],
  ['monitor-nm-running-gdbus', [], []],
  ['monitor-nm-state-gdbus', [], []]
]

incs = [
  top_inc,
  shared_inc,
  libnm_core_inc,
  libnm_inc
]

foreach example: examples
  executable(
    example[0],
    [example[0] + '.c'] + example[2],
    include_directories: incs,
    dependencies: [glib_dep] + example[1],
    c_args: '-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE'
  )
endforeach
