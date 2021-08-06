`NMDhcpClient`
==============

Using `NMDhcpClient` still requires a lot of logic in `NMDevice`. The main goal
is to simplify `NMDevice`, so `NMDhcpClient` must become more complicated to
provide a simpler (but robust) API.

NMDevice has basically two timeouts (talking about IPv4, but it applies
similarly to IPv6): `ipv4.dhcp-timeout` and `ipv4.required-timeout`. They
control how long NMDevice is willing to try, before failing the activation
altogether. Note that with `ipv4.may-fail=yes`, we may very well never want to
fail the activation entirely, regardless how DHCP is doing. In that case we
want to stay up, but also constantly retrying whether we cannot get a lease and
recover.

Currently, if `NMDhcpClient` signals a failure, then it's basically up to
`NMDevice` to schedule and retry. That is complicated, and we should move the
complexity out of `NMDevice`.

`NMDhcpClient` should have a simpler API:

- `nm_dhcp_manager_start_ip[46]()`: creates (and starts) a `NMDhcpClient`
  instance. The difference is, this function tries really hard not to fail
  to create an `NMDhcpClient`. There is no explicit `start()`, but note that the
  instance must not emit any signals before the next maincontext iteration. That is,
  it only will call back the user after a timeout/idle or some other IO event, which
  happens during a future iteration of the maincontext.

- `nm_dhcp_client_stop()`: when `NMDevice` is done with the `NMDhcpClient`
  instance, it will stop it and throw it away. This method exists because
  `NMDhcpClient` is a `GObject` and ref-counted. Thus, we don't want to rely on
  the last unref to stop the instance, but have an explicit stop. After stop, the
  instance is defunct and won't emit any signals anymore. The class does not need
  to support restarting a stopped instance. If `NMDevice` wants to restart DHCP, it
  should create a new one. `NMDevice` would only want to do that, if the parameters
  change, hence a new instance is in order (and no need for the complexity of
  restart in `NMDhcpClient`).

- as already now, `NMDhcpClient` is not very configurable. You provide most
  (all) parameters during `nm_dhcp_manager_start_ip[46]()`, and then it keeps
  running until stop.

- `NMDhcpClient` exposes a simple state to the user:

   1. "no lease, but good". When starting, there is no lease, but we are
      optimistic to get one. This is the inital state, but we can also get back to
      this state after we had a lease (which might expire).

   1. "has a lease". Here there is no need to distinguish whether the current
      lease was the first we received, or whether this was an update. In this state,
      the instance has a lease and we are good.

   1. "no lease, but bad". `NMDhcpClient` tries really hard, and "bad" does not
      mean that it gave up. It will keep retrying, it's just that there is little
      hope of getting a new lease. This happens, when you try to run DHCP on a Layer3
      link (WireGuard). There is little hope to succeed, but `NMDhcpClient`
      (theoretically) will retry and may recover from this. Another example is when
      we fail to start dhclient because it's not installed. In that case, we are not
      optimistic to recover, however `NMDhcpDhclient` will retry (with backoff
      timeout) and might still recover from this. For most cases, `NMDevice` will
      treat the no-lease cases the same, but in case of "bad" it might give up
      earlier.

When a lease expires, that does not necessarily mean that we are now in a bad
state. It might mean that the DHCP server is temporarily down, but we might
recover from that easily. "bad" really means, something is wrong on our side
which prevents us from getting a lease. Also, imagine `dhclient` dies (we would
try to restart, but assume that fails too), but we still have a valid lease,
then possibly `NMDhcpClient` should still pretend all is good and we still have
a lease until it expires. It may be we can recover before that happens. The
point of all of this, is to hide errors as much as possibly and automatically
recover. `NMDevice` will decide to tear down, if we didn't get a lease after
`ipv4.dhcp-timeout`. That's the main criteria, and it might not even
distinguish between "no lease, but good" and "no lease, but bad".

- `NMDhcpClient` will also take care of the `ipv4.dhcp-timeout` grace period.
  That timeout is provided during start, and starts ticking whenever there is
  no lease. When it expires, a timeout signal gets emitted. That's it. This is
  independent from the 3 states above, and only saves `NMDevice` from scheduling
  this timer themselves.
  This is NM_DHCP_CLIENT_NOTIFY_TYPE_NO_LEASE_TIMEOUT notification.

- for nettools, `nm_dhcp_client_can_accept()` indicates that when we receive a
  lease, we need to accept/decline it first. In that case, `NMDevice`
optionally does ACD first, then configures the IP address first and calls
`nm_dhcp_client_accept()`. In case of ACD conflict, it will call
`nm_dhcp_client_decline()` (which optimally causes `NMDhcpClient` to get a
different lease). With this, the above state "has a lease" has actually three
flavors: "has a lease but not yet ACD probed" and "has a lease but
accepted/declined" (but `NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED` gets only emitted
when we get the lease, not when we accept/decline it). With `dhclient`, when we
receive a lease, it means  "has a lease but accepted" right away.

- for IPv6 prefix delegation, there is also `needed_prefixes` and
  `NM_DHCP_CLIENT_NOTIFY_TYPE_PREFIX_DELEGATED`. Currently `needed_prefixes` needs
  to be specified during start (which simplifies things). Maybe `needed_prefixes`
  should be changable at runtime. Otherwise, whether we have prefixes is similar
  to whether we have a lease, and the simple 3 states apply.

When NetworkManager quits, it may want to leave the interface up. In that case,
we still always want to stop the DHCP client, but possibly not deconfiguring
the interface. I don't think that this concerns `NMDhcpClient`, because `NMDhcpClient`
only provides the lease information and `NMDevice` is responsible to configure it.
