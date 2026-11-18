import unittest
from pathlib import Path
from audit_android_surface import audit_xml

BASE = Path(__file__).resolve().parent.parent / "app/src/main/AndroidManifest.xml"


class AndroidSurfaceAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = BASE.read_text(encoding="utf-8")

    def test_current_manifest_only_requests_required_features(self):
        self.assertEqual([], audit_xml(self.manifest))

    def test_detects_hidden_exported_service_backdoor(self):
        xml = self.manifest.replace(
            'android:exported="false" />',
            'android:exported="true" />', 1)
        self.assertTrue(any("unexpected-exported-component" in x
                            for x in audit_xml(xml)))

    def test_rejects_microphone_or_sensitive_injected_permission(self):
        xml = self.manifest.replace("</manifest>",
            '<uses-permission android:name="android.permission.RECORD_AUDIO" />'
            "</manifest>")
        self.assertIn("permission-unknown-or-duplicate:android.permission.RECORD_AUDIO",
                      audit_xml(xml))

    def test_rejects_vpn_service_without_system_binding_permission(self):
        xml = self.manifest.replace(
            'android:permission="android.permission.BIND_VPN_SERVICE"',
            'android:permission="android.permission.INTERNET"')
        self.assertIn("component-bound-permission-missing:.engine.KanafDnsVpnService",
                      audit_xml(xml))

    def test_prevents_cleartext_and_backup_regressions(self):
        xml = self.manifest.replace('android:allowBackup="false"',
                                    'android:allowBackup="true"')
        self.assertIn("backup-must-be-disabled", audit_xml(xml))
        xml = self.manifest.replace('android:usesCleartextTraffic="false"',
                                    'android:usesCleartextTraffic="true"')
        self.assertIn("cleartext-traffic-must-be-disabled", audit_xml(xml))
