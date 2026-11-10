# Heuristic indicators

A heuristic hit is labeled suspicious, never malicious. An exact hash or a known-malware certificate is the only malicious result.

Threshold: **100**. A normal app is not flagged for size, R8 short names, DexClassLoader, or Play Feature Delivery. Those are normal in official apps such as YouTube.

| Signal | Weight | Notes |
| --- | ---: | --- |
| Overlay + accessibility service | 100 | Alone this crosses the threshold. Typical overlay fraud. |
| SMS read/receive + internet, and no launcher or another risk | 100 | A normal SMS app with a launcher is not flagged. |
| Device admin together with overlay, SMS, or no launcher | 100 | Device admin alone is not enough. |
| Known packer package prefix, with another risk | 100 | Matched as a class-name prefix, not a loose substring. |
| Debug certificate together with overlay, SMS, or a packer | 100 | A debug key alone is not enough. |
| Install packages + internet + no launcher + another risk | 100 | File managers and stores are not flagged. |

Installed packages under known store publishers (`com.google.`, `com.samsung.`, and the same kind of prefix) skip heuristics. Hash and certificate matches still apply.

An archive that is merely large, deep, or unreadable is not reported as a threat. Depth beyond the limit is still reported.

False-positive rate on a full store sample: **لم يُنفَّذ**. The YouTube-style case (launcher, internet, dynamic dex, heavy obfuscation) scores 0 in the unit test.
