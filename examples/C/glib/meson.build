examples = [
  ['add-connection-gdbus', [libnm_enum[1], nm_version_macro_header], [libnm_inc, shared_inc], [uuid_dep]],
  ['add-connection-libnm', [nm_version_macro_header], [shared_inc], [libnm_dep]],
  ['get-active-connections-gdbus', [libnm_enum[1], nm_version_macro_header], [libnm_inc, shared_inc], []],
  ['get-ap-info-libnm', [nm_version_macro_header], [shared_inc], [libnm_dep]],
  ['list-connections-gdbus', [], [], []],
  ['list-connections-libnm', [nm_version_macro_header], [shared_inc], [libnm_dep]],
  ['monitor-nm-running-gdbus', [], [], []],
  ['monitor-nm-state-gdbus', [], [], []],
]

foreach example: examples
  executable(
    example[0],
    [example[0] + '.c'] + example[1],
    include_directories: example[2],
    dependencies: [libnm_core_dep] + example[3],
  )
endforeach
