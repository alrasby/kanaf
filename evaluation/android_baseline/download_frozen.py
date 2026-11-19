#!/usr/bin/env python3
"""Fetch only the previously frozen SHA-256 manifest. Never execute samples."""
import concurrent.futures
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

def download(row, destination):
    sha = row['sha256']
    assert len(sha) == 64 and all(c in '0123456789abcdef' for c in sha)
    assert 0 < row['size'] <= 64 * 1024 * 1024
    url = row['url']
    assert url.startswith(('https://f-droid.org/repo/', 'https://raw.githubusercontent.com/ashishb/android-malware/'))
    path = destination / (sha + '.sample')
    if path.is_file() and path.stat().st_size == row['size'] and hashlib.sha256(path.read_bytes()).hexdigest() == sha:
        return sha
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(row['size'] + 1)
    assert len(data) == row['size'] and hashlib.sha256(data).hexdigest() == sha, sha
    path.write_bytes(data)
    path.chmod(0o600)
    return sha

if __name__ == '__main__':
    os.umask(0o077)
    manifest = json.loads(Path(sys.argv[1]).read_text())
    folder = Path(sys.argv[2])
    folder.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(download, row, folder) for row in manifest['samples']]
        for index, result in enumerate(concurrent.futures.as_completed(futures), 1):
            result.result()
            if index % 10 == 0:
                print(f'Verified {index}/{len(futures)}', flush=True)
