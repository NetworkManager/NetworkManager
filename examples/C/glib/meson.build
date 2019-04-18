examples = [
  ['add-connection-gdbus', [libnm_enum[1]], [libnm_inc], [uuid_dep]],
  ['add-connection-libnm', [], [], [libnm_dep]],
  ['get-active-connections-gdbus', [libnm_enum[1]], [libnm_inc], []],
  ['get-ap-info-libnm', [], [], [libnm_dep]],
  ['list-connections-gdbus', [], [], []],
  ['list-connections-libnm', [], [], [libnm_dep]],
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
