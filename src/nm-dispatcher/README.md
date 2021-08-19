nm-dispatcher
=============

Runs as a D-Bus activated, exit-on-idle service to execute
user scripts (dispatcher scripts) on certain events.

The user does not directly configure this service, it gets
controlled by NetworkManager. However, the user (or other
applications) would place scripts in certain directories for
the dispatcher service to execute them.

The systemd service is called `NetworkManager-dispatcher.service`.

See:
- `man 8 NetworkManager-dispatcher` ([[www]](https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html))
