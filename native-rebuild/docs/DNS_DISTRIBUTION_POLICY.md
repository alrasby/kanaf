# Kanaf DNS: isolated security and advertising policies

## Technical boundary (16 November 2026)

Each intercepted DNS hostname is classified by `DnsDomainPolicy` as:
- `SECURITY_THREAT`: only a separately confirmed malware/phishing DNS
  indicator, NOT advertising domains. **No production local security-domain
  feed is bundled today.** The Play candidate gets actual malware/phishing
  protection from the independent Cloudflare Security DoH resolver.
- `AD_TRACKER`: fixed legacy advertising/tracker host list **only in the
  current community distribution**.
- `ALLOWED`: forwarded to the sole allowed DoH endpoint using TLS validation.

**Default build remains unchanged:** AdGuard DNS standard/family plus local
ad/tracker blocking upon user-initiated VPN consent. It is NOT suitable for
Google Play in this state.

**Play DNS security-only candidate:** Build with `-PkanafPlayDnsSecurityOnly=true`.
- Local ad/tracker rule evaluation is disabled in the packet decision.
- `DnsProviderStore` accepts only `security.cloudflare-dns.com`;
  previous stored AdGuard preferences are normalized to this endpoint and
  provider-switch commands cannot enable AdGuard.
- Requests are sent to the independently documented
  `https://security.cloudflare-dns.com/dns-query` HTTPS endpoint for
  malware/phishing filtering without an advertising-filter service.
- UI, service notification, initial VPN disclosure, Quick Settings
  disclosure, and in-app privacy text describe the active policy.

### Run both build contracts

```sh
cd native-rebuild
gradle :app:testDebugUnitTest :app:assembleDebug
gradle -PkanafPlayDnsSecurityOnly=true \
  :app:testDebugUnitTest :app:assembleDebug :app:bundleDebug \
  :app:verifyKanafPlayDnsPolicy
```

`gradle :app:verifyKanafPlayDnsPolicy` must fail with
`KANAF_PLAY_DNS_POLICY_BLOCKED` when the flag is missing.
Both examples are **debug builds only**. Never upload a default
community APK/AAB or claim the Play candidate has received approval.

## Future genuine on-device security-domain data

A new domain-specific, legally redistributable threat feed must be
independently sourced, signed, reviewed, versioned, and rollback-resistant.
Only its authenticated domain records should be fed into
`verifiedThreatHosts`. Malicious APK hashes are NOT DNS domain
indicators. Never relabel advertising domains as malware.

## Not yet established

Android physical phone verification of DNS on IPv4/IPv6 and off/auto/strict
Private DNS, VPN stop and network switching, a public accurate privacy
policy and Play Console VpnService/declaration acceptance. The Cloudflare
endpoint blocks some phishing/malware domains on its own determination;
it does not establish full device DNS coverage or guarantee zero false positives.

Official primary sources:
- https://developers.cloudflare.com/1.1.1.1/setup/
- https://support.google.com/googleplay/android-developer/answer/12564964
- https://support.google.com/googleplay/android-developer/answer/16559646
