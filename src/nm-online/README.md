nm-online
=========

A small NetworkManager client that blocks until
NetworkManager is done configuring the interfaces.

This is not very useful to the end user. It is used
by `NetworkManager-wait-online.service` to determine
when NetworkManager is done with startup.

See:

- `man 1 nm-online` ([[www]](https://networkmanager.dev/docs/api/latest/nm-online.html))
- `systemctl cat NetworkManager-wait-online.service`
