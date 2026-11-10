# What this build cannot do

- **Signed APK:** `Kanaf.apk`, package `com.kanaf.alrasby`, version `1.0`, Android 7+. It is a sideload of the scanner UI plus the bundled signature files, not a device administrator.
- Installed-package scanning, uninstall dialogs, and the system App Info screen need Android. The browser scans only folders and files the person selects.
- Real-time install watching needs Android. Folder watching uses `FileSystemObserver` when the browser has it, and stays off when it does not. There is no polling loop.
- Scheduled scans run only while Kanaf is open.
- Inbox reading is not implemented. The message screen accepts pasted text (the share path).
- Silent delete does not exist. If the browser did not grant write access, delete fails and says so.
- Kanaf does not ship a DNS firewall, VPN, accessibility service, or device-admin receiver.
- Body signatures that need libclamav are not used.
- Redirect expansion runs in the browser. If CORS blocks it, Kanaf says so and does not send the address to its own server.
