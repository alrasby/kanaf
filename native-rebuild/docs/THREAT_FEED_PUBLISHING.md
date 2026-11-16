# Kanaf threat-feed publisher checklist

This tooling prepares the **existing SHA-256 feed format** only. It does not
turn the native EICAR-only ClamAV/YARA-X rules into a production antivirus.
**Do not publish a release with the EICAR-only test fixture as a malware feed.**

## Publisher operation (offline only)

1. License/validate each source of real threat hashes, track provenance, and
   validate against an independent benign corpus to measure false positives.
2. Generate a long-term RSA private signing key in an OFFLINE security-controlled
   environment. Protect it with encryption or a hardware security module, and
   never commit it or copy it to CI, an APK, or a web server. Derive an X.509
   SubjectPublicKeyInfo DER public key with OpenSSL.
3. Prepare a UTF-8 \`signatures.tsv\` file. Each non-comment record:
   \`<64-lowercase-SHA256-hex><TAB><evidence-derived-classification-label>\`.
   Keep under 32 MiB; ensure every hash and label is licensed, verified, and
   accurately classified; never infer malware from an extension or permission.
4. Sign offline:
   \`python3 tools/signed_feed.py sign --database signatures.tsv --private-key /secure/signing-private.pem --version 1 --output kanaf-signatures.zip\`
5. Verify independently with the publisher public key:
   \`python3 tools/signed_feed.py verify --zip kanaf-signatures.zip --public-key /secure/signing-public.pem\`
6. Host the ZIP over HTTPS at a **publisher-controlled URL**, without redirects.
   The build must pin only the verified public key through Gradle properties
   \`kanafSignaturePublicKeyBase64\` (DER Base64),
   \`kanafSignatureMinVersion\` (positive monotonic version),
   \`kanafSignatureFeedHttpsUrl\` (HTTPS ZIP URL). Release operations must
   increment version strictly on every new database and never redistribute
   unauthorised threat intelligence.
7. Before a release, verify the installed database via Android, fail/recover
   tests (truncated download, tampered digest, wrong signer, rollback),
   inspection of the resulting signed APK/AAB, and real threat/benign evaluation.

CI tests use short-lived synthetic **test** signing keys, generated only for
fixture tests and discarded afterward. They are not production keys. The
current debug build remains intentionally UNCONFIGURED for real updates.

**Remaining external inputs:** legally licensed curated real-malware feed,
publisher-owned offline key, independently validated threat samples and false
positive results, hardware Android QA, Play Console sensitive permission
declarations, and signed release approval.

## Production first-use trust chain

When the app binary has an app-pinned minimum signature version and RSA public
key, `SignatureRepository.load()` now verifies
`assets/production_signatures.zip` on first use and atomically installs it.
Subsequent signed downloads/upgrades must be strictly newer; a corrupt ZIP,
wrong signer, missing key, missing asset, or legacy unverified state cannot
fall back to debug signatures. Test-only EICAR assets remain for debug engine
self-tests, NOT actual production file scans. For native scanning, the APK
requires separately hash-pinned `production_clamav.ndb` and
`production_yara.yar` assets. Their content still needs external licensing,
provenance, and accuracy audits before it can be designated production-ready.
