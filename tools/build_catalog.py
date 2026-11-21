#!/usr/bin/env python3
"""녹음 목록(catalog.enc)과 암호화된 녹음(audio/*.bin)을 만든다.

- 목록은 가족 암호(STORY_PASS)로 잠근다 (PBKDF2-SHA256 → AES-GCM).
- 녹음은 목록 안에 든 콘텐츠 키(K)로 잠근다. 암호를 바꿔도 녹음은 다시 올릴 필요가 없다.
- 공개 저장소에는 Drive 파일 ID가 드러나지 않게, 녹음 파일 이름은 HMAC(K, Drive ID)로 만든다.

사용:
  STORY_PASS=... python3 tools/build_catalog.py --csv 목록.csv [--audio-dir 변환된m4a폴더] [--durations durations.txt]
  (--audio-dir의 파일 이름은 '<Drive ID>.m4a')
"""
import argparse, base64, csv, hashlib, hmac, json, os
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 210_000
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
b64e = lambda x: base64.b64encode(x).decode()
b64d = base64.b64decode


def derive(password, salt, it=ITER):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(password.encode())


def open_catalog(path, password):
    e = json.load(open(path))
    key = derive(password, b64d(e['salt']), e['iter'])
    return json.loads(AESGCM(key).decrypt(b64d(e['iv']), b64d(e['ct']), None))


def seal_catalog(obj, password):
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive(password, salt)).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode(), None)
    return {'v': 2, 'iter': ITER, 'salt': b64e(salt), 'iv': b64e(iv), 'ct': b64e(ct)}


def token(K, drive_id):
    return hmac.new(K, drive_id.encode(), hashlib.sha256).hexdigest()[:20]


def split(v):
    return [x.strip() for x in str(v or '').replace('，', ',').split(',') if x.strip()]


def to_iso(v):
    for fmt in ('%m/%d/%Y', '%m/%d/%Y %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(v.strip(), fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', required=True)
    ap.add_argument('--audio-dir')
    ap.add_argument('--durations')
    ap.add_argument('--overrides', help='JSON {Drive ID: {title, reader, ...}} — 시트보다 우선')
    a = ap.parse_args()
    password = os.environ['STORY_PASS']
    cat_path = os.path.join(ROOT, 'catalog.enc')

    old = {}
    K = None
    if os.path.exists(cat_path):
        try:
            prev = open_catalog(cat_path, os.environ.get('STORY_PASS_OLD', password))
            K = b64d(prev['key']) if prev.get('key') else None
            old = {i['src']: i for i in prev.get('items', []) if i.get('src')}
        except Exception:
            pass
    K = K or os.urandom(32)

    durs = {}
    if a.durations:
        for line in open(a.durations):
            p = line.split()
            if len(p) == 2:
                durs[p[0]] = round(float(p[1]))
    over = json.load(open(a.overrides)) if a.overrides else {}

    os.makedirs(os.path.join(ROOT, 'audio'), exist_ok=True)
    items = []
    with open(a.csv, encoding='utf-8') as f:
        for r in csv.DictReader(f):
            did = (r.get('fileId') or '').strip()
            if not did:
                continue
            tok = token(K, did)
            out = os.path.join(ROOT, 'audio', tok + '.bin')
            if a.audio_dir:
                src = os.path.join(a.audio_dir, did + '.m4a')
                if os.path.exists(src) and not os.path.exists(out):
                    iv = os.urandom(12)
                    with open(out, 'wb') as w:
                        w.write(iv + AESGCM(K).encrypt(iv, open(src, 'rb').read(), None))
            if not os.path.exists(out):
                continue  # 녹음이 아직 없으면 목록에서 뺌
            o = over.get(did, {})
            title = (o.get('title') or r.get('제목') or '').strip() or (old.get(did, {}).get('title') or '')
            untitled = not title or title.startswith('이야기 ') and title[4:].isdigit()
            if untitled:
                title = '이야기 ' + str(len(items) + 1)
            items.append({
                'id': tok, 'src': did, 'title': title,
                'reader': o.get('reader') or (r.get('읽은 사람') or '').strip(),
                'category': o.get('category') or (r.get('분류') or '').strip(),
                'keywords': o.get('keywords') or split(r.get('키워드')),
                'summary': o.get('summary') or (r.get('요약') or '').strip(),
                'playlists': o.get('playlists') or split(r.get('재생목록(직접)')),
                'added': to_iso(r.get('추가일') or ''),
                'untitled': untitled,
                'dur': durs.get(did) or old.get(did, {}).get('dur') or 0,
            })
    cat = {'updated': datetime.now(timezone.utc).isoformat(), 'key': b64e(K), 'items': items}
    json.dump(seal_catalog(cat, password), open(cat_path, 'w'))
    titled = sum(1 for i in items if not i['untitled'])
    print(f'{len(items)}개 (제목 있음 {titled}개) → catalog.enc')


if __name__ == '__main__':
    main()
