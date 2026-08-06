nm-initrd-generator
===================

A command line tool that generates NetworkManager configuration.

It runs in the initrd, before NetworkManager starts. It parses the kernel
command line, writes connection profiles to
`/run/NetworkManager/system-connections`, and quits.

The generator only writes configuration. A separate NetworkManager instance
applies it, started by the `*-initrd.service` units in `data/` and wired into
`initrd.target` by the `nm-initrd-generator.sh` systemd generator. dracut
drives all this from its own `35network-manager` module, but the units are
deliberately not tied to dracut, so other systemd-based initramfs generators
can use them.

See:
- `man 8 nm-initrd-generator` ([[www]](https://networkmanager.dev/docs/api/latest/nm-initrd-generator.html))
- `man 7 dracut.cmdline`
- `systemctl cat NetworkManager-initrd.service`
