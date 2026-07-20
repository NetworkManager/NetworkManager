#!/bin/bash

set -ex

# The image strips non-English locales via NoExtract but the nmcli l10n test
# needs pl_PL
echo 'NoExtract = !usr/share/i18n/locales/pl_PL' >> /etc/pacman.conf

# Partial upgrades are unsupported, so upgrade everything first
pacman -Syu --noconfirm
pacman -S --noconfirm glibc

NM_INSTALL="pacman -S --needed --noconfirm" bash -x ./contrib/arch/REQUIRED_PACKAGES

sed -i 's/^#\(en_US.UTF-8 UTF-8\)/\1/;s/^#\(pl_PL.UTF-8 UTF-8\)/\1/' /etc/locale.gen
locale-gen
