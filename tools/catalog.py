#!/usr/bin/env python3
"""catalog.enc 다루기 (목록의 원본은 catalog.enc 자체).

  STORY_PASS=... python3 tools/catalog.py show                      # 요약
  STORY_PASS=... python3 tools/catalog.py dump > items.json          # 풀어서 보기
  STORY_PASS=... python3 tools/catalog.py update edits.json          # {id: {title, reader, ...}} 덮어쓰기
  STORY_PASS=... python3 tools/catalog.py add items.json             # [{id, title, ...}] 추가(같은 id는 덮어씀)
  STORY_PASS=... python3 tools/catalog.py inbox <owner/repo> <토큰파일>   # 녹음함 설정
  STORY_PASS=... NEW_PASS=... python3 tools/catalog.py repass        # 가족 암호 바꾸기(녹음은 그대로)
"""
import base64, json, os, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 210_000
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.environ.get('CATALOG', os.path.join(ROOT, 'catalog.enc'))
b64e = lambda x: base64.b64encode(x).decode()
b64d = base64.b64decode


def derive(pw, salt, it=ITER):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(pw.encode())


def load(pw):
    e = json.load(open(PATH))
    return json.loads(AESGCM(derive(pw, b64d(e['salt']), e['iter'])).decrypt(b64d(e['iv']), b64d(e['ct']), None))


def save(cat, pw):
    cat['updated'] = datetime.now(timezone.utc).isoformat()
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive(pw, salt)).encrypt(iv, json.dumps(cat, ensure_ascii=False).encode(), None)
    json.dump({'v': 2, 'iter': ITER, 'salt': b64e(salt), 'iv': b64e(iv), 'ct': b64e(ct)}, open(PATH, 'w'))


def main():
    pw = os.environ['STORY_PASS']
    cmd = sys.argv[1]
    cat = load(pw)
    items = cat.setdefault('items', [])
    by = {i['id']: i for i in items}
    if cmd == 'show':
        t = sum(1 for i in items if not i.get('untitled'))
        print(f"녹음 {len(items)}개 (제목 있음 {t}), 녹음함: {(cat.get('inbox') or {}).get('repo', '없음')}, "
              f"갱신 {cat.get('updated')}")
        return
    if cmd == 'dump':
        json.dump(cat if '--all' in sys.argv else items, sys.stdout, ensure_ascii=False, indent=1)
        return
    if cmd == 'update':
        for k, v in json.load(open(sys.argv[2])).items():
            if k in by:
                by[k].update(v)
                if v.get('title'):
                    by[k]['untitled'] = False
    elif cmd == 'add':
        for it in json.load(open(sys.argv[2])):
            if it['id'] in by:
                by[it['id']].update(it)
            else:
                items.append(it)
                by[it['id']] = it
    elif cmd == 'inbox':
        cat['inbox'] = {'repo': sys.argv[2], 'token': open(sys.argv[3]).read().strip()}
    elif cmd == 'repass':
        pw = os.environ['NEW_PASS']
    else:
        sys.exit('모르는 명령: ' + cmd)
    save(cat, pw)
    print(f'저장: 녹음 {len(items)}개')


if __name__ == '__main__':
    main()
