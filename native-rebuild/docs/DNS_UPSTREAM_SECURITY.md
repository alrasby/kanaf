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
Provider selection is saved locally and applies upon starting the VPN.
Switch off Kanaf DNS first to change the selected provider.

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
