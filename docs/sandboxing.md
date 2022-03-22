Sandboxing of NetworkManager Daemon
===================================

NetworkManager runs as root user, although it might also be possible to run
as a separate user ([#843](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/issues/843)).

The daemon requires certain permissions to perform its tasks, but it also
runs network facing code (like the DHCP library). We should better sandbox
the process to mitigate exploitable bugs.

We want to drop unrequired Capabilities and confine the daemon with SELinux.
The SELinux policy is maintained on downstream distributions.

For dropping capabilities, we use Systemd's `CapabilityBoundingSet`.

Another idea would be to run network facing code (DHCP) as a separate sandboxed process
or to rewrite in a safe(er) language. Both is high effort and not clear to be worth
it. Possibly that effort would be better spent in fuzzing and improved unit testing
of the code.

See also [#71](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/issues/71).


Certificate Files
-----------------

For 802-1x and VPN plugins, the connection profile can contain files.
Files are highly problematic because they might be owned by a different
user or not have the right SELinx context (`~/.cert/`). Also, they make the
profile not self-contained and are hard to cleanup when deleting the file.

NetworkManager itself does not much with certificate files, mostly they are just
passed on to wpa_supplicant or the VPN plugin. Wpa_supplicant in turn is not yet
sandboxed (that is a problem?!), and can usually read the files (by having `CAP_DAC_OVERRIDE`).

One aim is to drop `CAP_DAC_OVERRIDE` capability. So let's focus on that.
But there are similar other problems with files.

Possible Solutions:

- NetworkManager mostly read the certificate files to determine whether a secret
  is needed. We could just pass them on to supplicant, and supplicant needs a way
  to call back and request more secrets. That is how VPN plugins work.

- move away from files and use PKCS#11 URIs and have a certificate store.

- for simple questions like is-file-valid-certificate or is-passwd-valid
  we could ask nm-priv-helper via D-Bus. The problem is that such requests
  would be asynchronous and currently the code expects an answer right away.
  But even a higher privileged service like nm-priv-helper might be confined
  by SELinux or the file might be on a fuse filesystem. Files just don't
  work well.

- drop `CAP_DAC_OVERRIDE` and expect users either to not use 802-1x with certificates,
  to have the certificates with suitable permissions, or to grant `CAP_DAC_OVERRIDE`
  to NetworkManager.service. We do the same already w.r.t. the SELinux context.

- document that users can drop `CAP_DAC_OVERRIDE` themselves (insecure by default),
  if they either don't use 802-1x certificates or make sure that the file permissions
  are suitable.

See [@8021x_tls](https://gitlab.freedesktop.org/NetworkManager/NetworkManager-ci/-/merge_requests/998)
test for reproducing a problem.


VPN Plugins
-----------

The NetworkManager process spawns the VPN plugins, that means the plugins
inherit all sandboxing from the daemon. That is a problem, because we don't
necessarily know what capabilities the VPN plugin will require and we tend
to just have capabilities because a VPN plugin might use it.

The solution is to let somebody else (with elevated privileges) spawn the
plugins.

This could be done by running the VPN plugins a separate systemd service. That would
be great, but has two severe downsides: it would only work with systemd and break
non-systemd use cases. More importantly, all existing plugins need to be update
for this new way of running. That could be done, however, there will be a transitioning
period during which we would need both ways to run the plugin. This means there
is a need to implement a systemd-less approach, and once we implement that, the
incentive for using systemd decreased. It still could be done maybe in the future.

The better way is to have our own VPN plugin runner. That could be `nm-priv-helper.service`.
It already runs as a separate service with distinct environment and sandboxing.
Note that spawning the VPN plugin process is already an async operation. So replacing
that with an async call to nm-priv-helper will be relatively straight forward.


Can we Drop a Capability?
-------------------------

### `CAP_DAC_OVERRIDE`:

1) Used for [VPN Plugins](#vpn-plugins).
  See there for how to solve that.

2) Used for 802-1x [certificate files](#certificate-files).
  See there for how to solve that.


Other systemd Sandboxing Options
--------------------------------

Enable sandboxing options possible. Again, the main problem are certificate files in802-1x
and VPN plugins.

Enable them one at a time, and open issues/merge-request for discussion.
