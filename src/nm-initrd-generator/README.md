nm-initrd-generator
===================

A command line tool that generates NetworkManager configuration.

This is supposed to be run by dracut in initrd, before NetworkManager
starts. It parses the kernel command line, generates configuration
and quits.

See:
- `man 8 nm-initrd-generator` ([[www]](https://networkmanager.dev/docs/api/latest/nm-initrd-generator.html))
- `man 7 dracut.cmdline`
