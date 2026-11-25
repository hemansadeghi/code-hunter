#!/usr/bin/env python3
"""Scan locally supplied, authorized images for candidate DK codes."""
import argparse
import hashlib
import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, ImageOps
import pytesseract

PATTERN = re.compile(r'(?<![A-Z0-9])DK[A-Z0-9]{3,4}(?![A-Z0-9])')
EXTS = {'.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tiff'}

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def inspect(path):
    with Image.open(path) as raw:
        im = ImageOps.exif_transpose(raw).convert('L')
        im = ImageOps.autocontrast(im)
        if im.width < 1400:
            scale = min(3, 1400 / im.width)
            im = im.resize((int(im.width * scale), int(im.height * scale)))
        else:
            scale = 1
        results = {}
        for psm in (11, 6):
            data = pytesseract.image_to_data(im, lang='eng', config=f'--psm {psm}', output_type=pytesseract.Output.DICT, timeout=30)
            for i, token in enumerate(data['text']):
                for match in PATTERN.finditer(token.upper()):
                    code = match.group()
                    conf = float(data['conf'][i])
                    if conf < 0:
                        continue
                    box = [round(data[k][i] / scale) for k in ('left', 'top', 'width', 'height')]
                    candidate = {'code': code, 'ocr_confidence': round(conf, 1), 'bbox_xywh': box}
                    if code not in results or conf > results[code]['ocr_confidence']:
                        results[code] = candidate
        return list(results.values())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--watch', action='store_true')
    parser.add_argument('--interval', type=int, default=10)
    parser.add_argument('--db', type=Path, default=Path('hunter.sqlite3'))
    args = parser.parse_args()
    if not args.folder.is_dir():
        parser.error('folder must exist')
    if args.interval < 1:
        parser.error('interval must be at least 1 second')
    db = sqlite3.connect(args.db)
    db.execute('CREATE TABLE IF NOT EXISTS scanned (sha256 TEXT PRIMARY KEY, scanned_at TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS hits (sha256 TEXT NOT NULL, code TEXT NOT NULL, details TEXT NOT NULL, PRIMARY KEY(sha256, code))')
    while True:
        for path in sorted(args.folder.rglob('*')):
            if not path.is_file() or path.suffix.lower() not in EXTS:
                continue
            try:
                sha = hashlib.sha256(path.read_bytes()).hexdigest()
                if db.execute('SELECT 1 FROM scanned WHERE sha256=?', (sha,)).fetchone():
                    continue
                hits = inspect(path)
                stamp = utc_now()
                with db:
                    for hit in hits:
                        hit.update(image=str(path.resolve()), detected_at=stamp, sha256=sha, validity='unverified')
                        details = json.dumps(hit, ensure_ascii=False)
                        db.execute('INSERT OR IGNORE INTO hits VALUES (?, ?, ?)', (sha, hit['code'], details))
                        print(details, flush=True)
                    db.execute('INSERT OR IGNORE INTO scanned VALUES (?, ?)', (sha, stamp))
                print(f'Scanned {path}: {len(hits)} candidate(s)', flush=True)
            except (OSError, RuntimeError, ValueError) as exc:
                print(f'Error {path}: {exc}', flush=True)
        if not args.watch:
            break
        time.sleep(args.interval)
    db.close()

if __name__ == '__main__':
    main()
