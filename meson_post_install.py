#!/usr/bin/env python3

import os
import sys

if not os.environ.get('DESTDIR'):
  datadir = sys.argv[1]
  bindir = sys.argv[2]
  pkgconfdir = sys.argv[3]
  pkglibdir = sys.argv[4]
  localstatedir = sys.argv[5]

  completions_dir = os.path.join(datadir, 'bash-completion', 'completions')
  os.rename(os.path.join(completions_dir, 'nmcli-completion'), os.path.join(completions_dir, 'nmcli'))

  nmtui_alias = ['nmtui-connect', 'nmtui-edit', 'nmtui-hostname']
  src = os.path.join(bindir, 'nmtui')
  [os.symlink(src, os.path.join(bindir, dst))
   for dst in nmtui_alias]

  dst_dirs = [
    os.path.join(pkgconfdir, 'conf.d'),
    os.path.join(pkgconfdir, 'system-connections'),
    os.path.join(pkgconfdir, 'dispatcher.d', 'no-wait.d'),
    os.path.join(pkgconfdir, 'dispatcher.d', 'pre-down.d'),
    os.path.join(pkgconfdir, 'dispatcher.d', 'pre-up.d'),
    os.path.join(pkgconfdir, 'dnsmasq.d'),
    os.path.join(pkgconfdir, 'dnsmasq-shared.d'),
    os.path.join(pkglibdir, 'conf.d'),
    os.path.join(pkglibdir, 'VPN'),
    os.path.join(localstatedir, 'lib', 'NetworkManager')
  ]
  [os.makedirs(dst_dir)
   for dst_dir in dst_dirs
   if not os.path.exists(dst_dir)]

  if sys.argv[6] == 'install_docs':
    mandir = sys.argv[7]

    src = os.path.join(mandir, 'man1', 'nmtui.1')
    [os.symlink(src, os.path.join(mandir, 'man1', dst + '.1'))
     for dst in nmtui_alias]

    src = os.path.join(mandir, 'man5', 'NetworkManager.conf.5')
    dst = os.path.join(mandir, 'man5', 'nm-system-settings.conf.5')
    os.symlink(src, dst)
