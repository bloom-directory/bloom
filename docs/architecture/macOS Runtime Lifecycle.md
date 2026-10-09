# macOS runtime lifecycle

The root lifecycle monitor provisions the volatile
`/private/var/run/bloom/<login_uid>` directory tree before publishing platform
status or inspecting the login sentinel. Reboot can remove this tree while the
enrollment and custody state remain installed.

Provisioning uses numeric principals from the validated root-owned enrollment
and the same directory owners, groups, and modes as the privileged installer.
Missing directories start private, then receive their final ownership and mode.
Existing symlinks, non-directories, or directories with unexpected ownership or
permissions are rejected without modification. Provisioning never changes
custody, policy, approval, identity, or socket contents.

Directory provisioning does not authorize service activation. The monitor still
requires a running login sentinel and validates its socket's enrolled owner,
group, mode, and type before restarting that enrollment's Broker or Signer.
Broker and Signer retain their authenticated session checks. An absent sentinel
therefore leaves both service principals inactive even after runtime provisioning.

The installer loads the sentinel into `user/<login_uid>`. The monitor checks
that canonical job while also requiring the GUI login domain to exist. A
stopped or absent sentinel, or a user-domain job left after the GUI login is
gone, does not authorize a restart. Losing the authenticated sentinel connection
still drains Broker and Signer. W0 verifies this by booting out the sentinel,
observing both services exit, restoring the same user-domain job, and checking
that authenticated service readiness returns.
