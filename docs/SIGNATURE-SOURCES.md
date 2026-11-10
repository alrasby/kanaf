# Signature sources

Counts below are what the build embedded on 19 Oct 2026. The app shows the same numbers from `public/signatures/manifest.json`.

| Source | Version | Hash or record count | Check | License |
| --- | --- | ---: | --- | --- |
| ClamAV daily.cvd | 28157 | 54,705 hash rows | Legacy freshclam RSA over the body MD5, then MD5 of the gzip body | Hash records only. libclamav is not included. https://www.clamav.net/ |
| ClamAV main.cvd | 63 | 207,432 filtered hash rows (CVD reports 3,287,027 of all types) | Same signature check | Filtered to Android, Java, script, archive, and document families |
| URLhaus text | 2026-10-19 | 73,351 URLs | HTTPS download, line format checked | https://urlhaus.abuse.ch/api/ |
| MalwareBazaar recent | 2026-10-19 | 1,747 hashes | Hex length checked | https://bazaar.abuse.ch/faq/#tos — public export still answered on 19 Oct 2026; abuse.ch said auth keys become required on 21 Oct 2026 |
| CSCB | 2026-10-19 | 408 SHA-256 thumbprints | Hex length checked | https://bazaar.abuse.ch/faq/#cscb |

Mirrors: `database.clamav.net` returned HTTP 403 from this network. `packages.microsoft.com/clamav/daily.cvd` and `main.cvd` verified against the ClamAV public key, so the bytes are the signed Cisco databases.

EICAR (`44d88612…` / `275a021b…`, 68 bytes) is inside the official daily hash files. It is a test string, not a virus.
