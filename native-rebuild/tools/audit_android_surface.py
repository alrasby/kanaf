#!/usr/bin/env python3
"""Deterministic manifest permission/export audit; no claim of pentest coverage."""
import argparse
from pathlib import Path
import xml.etree.ElementTree as ET

A = "{http://schemas.android.com/apk/res/android}"
ALLOWED_PERMISSIONS = {
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
}
EXPECTED_EXPORTED = {
    (".MainActivity", "activity"): (True, None),
    (".engine.KanafDnsVpnService", "service"):
        (True, "android.permission.BIND_VPN_SERVICE"),
    (".engine.KanafDnsTileService", "service"):
        (True, "android.permission.BIND_QUICK_SETTINGS_TILE"),
}


def audit_xml(xml: str):
    problems = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return ["android-manifest-invalid-xml"]
    if root.tag != "manifest":
        return ["android-manifest-root-invalid"]
    perms = root.findall("uses-permission")
    seen = set()
    for entry in perms:
        name = entry.get(A + "name")
        if not name or name in seen or name not in ALLOWED_PERMISSIONS:
            problems.append("permission-unknown-or-duplicate:" + str(name))
        seen.add(name)
        if name == "android.permission.READ_EXTERNAL_STORAGE":
            value = entry.get(A + "maxSdkVersion")
            if not value or not value.isdigit() or int(value) > 32:
                problems.append("legacy-storage-permission-missing-cap")
    app = root.find("application")
    if app is None:
        return problems + ["application-missing"]
    if app.get(A + "allowBackup") != "false":
        problems.append("backup-must-be-disabled")
    if app.get(A + "usesCleartextTraffic") != "false":
        problems.append("cleartext-traffic-must-be-disabled")
    if app.get(A + "debuggable") == "true":
        problems.append("manifest-must-not-force-debuggable")
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for element in app.findall(tag):
            name = element.get(A + "name", "")
            exported_raw = element.get(A + "exported")
            if exported_raw not in ("true", "false"):
                problems.append("component-export-missing:" + name)
                continue
            exported = exported_raw == "true"
            expected = EXPECTED_EXPORTED.get((name, tag))
            if expected:
                should_export, required_permission = expected
                if exported != should_export:
                    problems.append("component-export-mismatch:" + name)
                if required_permission and element.get(A + "permission") != required_permission:
                    problems.append("component-bound-permission-missing:" + name)
            elif exported:
                problems.append("unexpected-exported-component:" + name)
            if tag == "service" and name == ".engine.NativeScannerService":
                if element.get(A + "process") != ":scanner" or exported:
                    problems.append("scanner-not-private-process")
    for expected, tag in ((n,t) for (n,t) in EXPECTED_EXPORTED):
        if app.find(f"{tag}[@{A}name='{expected}']") is None:
            problems.append("mandatory-component-missing:" + expected)
    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path,
                        default=Path(__file__).resolve().parent.parent /
                        "app/src/main/AndroidManifest.xml")
    args = parser.parse_args()
    problems = audit_xml(args.manifest.read_text(encoding="utf-8"))
    if problems:
        raise SystemExit("KANAF_ANDROID_SURFACE_AUDIT_FAILED: " +
                         ", ".join(problems))
    print("Android source manifest: minimal expected permission/export surface verified.")
    print("Not a proof of zero vulnerabilities; merged release manifest still needs review.")


if __name__ == "__main__":
    main()
