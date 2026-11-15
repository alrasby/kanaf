# Kanaf DNS — current network/security boundary

The Kanaf local DNS-only VPN routes only intercepted IPv4 UDP DNS packets.
It filters known ad/tracker hostnames locally and forwards allowed DNS wire
queries over authenticated HTTPS POST (RFC 8484) to the *single* selected
AdGuard DNS provider. Android `Network.openConnection(https://...)` binds the
HTTPS connection to an underlying non-VPN Android Network; TLS hostname and
certificate validation remain mandatory. No UDP/53 fallback is permitted.

Presets: `dns.adguard-dns.com` (default), `family.adguard-dns.com`
(family), and `dns.adguard.com` (legacy UI alias routed to the CURRENT
published standard hostname rather than inventing a legacy server).
Provider selection is saved locally. While Kanaf DNS is running, activating a
different provider first probes its authenticated DoH endpoint on an underlay
network; only on success does the service switch the in-memory upstream and
persist the new provider. The existing VPN tunnel remains established, and
the previous provider stays selected if preflight fails. Choosing the active
provider's off switch explicitly closes the VPN tunnel; switching is blocked
while another change is in progress.

Android system Private DNS **Off and Automatic** are supported without ADB.
Strict user-specified Private DNS **Provider** mode remains incompatible:
the app never silently changes a security setting. System **Off** and **Auto**
buttons open Android's own Private DNS settings. On Android Automatic, Kanaf
forwards all its intercepted requests encrypted over HTTPS, even if the
underlying network advertises an encrypted resolver.

The VPN MUST probe the chosen provider with an HTTPS DNS request before
establishing its local route; if unreachable it fails closed and does not
capture DNS. After connection, a provider/network failure returns SERVFAIL
rather than insecure fallback. The user can disable the VPN and use Android
Private DNS normally. Internet access still depends on the chosen server and
underlying network; test on physical Samsung phones before release.

Limitations: other VPNs cannot coexist, HTTPS/DoH from individual apps
is not intercepted, IPv6 DNS can bypass the IPv4-only route, and same-domain
or first-party advertising is outside the blocklist. This is not global
system-wide ad blocking and does not decrypt HTTPS.

## Ordinary-user setup (no ADB)
- Leave Android **Private DNS = Automatic** (or Off); choose one of the three presets in Kanaf, then switch the filter ON after Android's standard VPN consent. The two Off/Automatic buttons open Android's Settings directly; they never write privileged global settings.
- On Android 13+, **Add Kanaf DNS to Quick Settings** requests native system tile installation. Older versions provide a manual Quick Settings Edit instruction.
- The consumer manifest does not request `WRITE_SECURE_SETTINGS`, root, Accessibility, or ADB. Unknown/strict OS private DNS remains a deliberate closed gate.
- Leaving the app wipes the in-memory recent scan report; in-flight automatic scans are canceled. The signed detection engines remain under the Settings page, not the Home page.

## DNS session diagnostics and platform VPN state
- The DNS screen reports **aggregate counters for the current VPN session**:
  blocked by local ad/tracker rules, successfully forwarded DNS requests, and
  failures (including SERVFAIL); it stores no hostnames, query payloads, IPs,
  timestamps, or browsing history. The counters disappear when the VPN stops.
- The on-demand diagnostic checks whether the selected encrypted upstream
  answers a DNS-over-HTTPS probe and whether any underlying network advertises
  an IPv6 DNS server. IPv6 DNS may bypass this IPv4-only VPN, and app-owned
  encrypted DNS may also bypass it. A negative IPv6 observation **does not**
  certify leak prevention. This is a coverage assessment, not a device-wide
  DNS leak detector.
- Disabling Kanaf DNS uses an explicit STOP action, immediately closes the
  Android VPN interface and then stops the foreground service. Android's
  VPN settings may **still list Kanaf as a saved VPN profile** after successful
  disconnect. This is not evidence of a live tunnel; Android, not an
  unprivileged app, controls saved VPN profile removal. Verify the connected
  indicator or use Android's VPN detail screen to distinguish the states.
- Validate on a physical Samsung device over Wi-Fi and cellular, including
  Automatic and Off system Private DNS, switching all presets, denial of VPN
  consent, disconnect while preflight is pending, device screen-off, and
  Android Always-on VPN settings. Emulator/packet unit tests do not replace
  these checks.
