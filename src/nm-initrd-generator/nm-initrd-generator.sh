#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# initrd-specific units
initrd_units=(
    NetworkManager-config-initrd.service
    NetworkManager-initrd.service
    NetworkManager-wait-online-initrd.service
)

# host-specific units
host_units=(
    NetworkManager.service
    NetworkManager-dispatcher.service
    NetworkManager-wait-online.service
)

# Get generator normal directory
normal_dir=$1

# Since NetworkManager-initrd.service and NetworkManager.service are allocated
# for the same bus name org.freedesktop.NetworkManager, we should mask one of
# them depending on if we are in the initrd or on the host.
if [ "$SYSTEMD_IN_INITRD" != 1 ]; then
    # Mask initrd units in the host
    for unit in "${initrd_units[@]}"; do
        ln -s /dev/null "$normal_dir"/"$unit" 2> /dev/null
    done
    # Nothing else to do
    exit 0
fi

# Mask host units in the initrd
for unit in "${host_units[@]}"; do
    ln -s /dev/null "$normal_dir"/"$unit" 2> /dev/null
done

# Install initrd units in the unit file hierarchy
mkdir -p "$normal_dir"/initrd.target.wants
mkdir -p "$normal_dir"/network-online.target.wants
for unit in "${initrd_units[@]}"; do
    ln -s /usr/lib/systemd/system/"$unit" \
        "$normal_dir"/initrd.target.wants/"$unit"
    if [ "$unit" = "NetworkManager-wait-online-initrd.service" ]; then
        ln -s /usr/lib/systemd/system/"$unit" \
            "$normal_dir"/network-online.target.wants/"$unit"
    fi
done

exit 0
