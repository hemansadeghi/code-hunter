#!/usr/bin/env python3
"""Permission-scoped, rate-limited public website OCR crawler."""
import argparse, hashlib, json, re, sqlite3, sys, tempfile, time
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree as ET
import requests
from bs4 import BeautifulSoup
from hunter import inspect, utc_now, PATTERN

UA = 'CodeHunterResearch/2.0'
MAX_BYTES = 12 * 1024 * 1024

def canonical(base, link):
    try:
        p = urlsplit(urljoin(base, link.strip()))
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.port not in (None,80,443):
            return None
        return urlunsplit((p.scheme,p.netloc.lower(),p.path or '/',p.query,''))
    except ValueError:
        return None

def codes(text):
    return sorted(set(PATTERN.findall(text.upper())))

def html_items(url, html):
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.get_text(' ',strip=True) if soup.title else ''
    links = [canonical(url,a['href']) for a in soup.select('a[href]')]
    imgs = []
    for node in soup.select('img, source'):
        for attr in ('src','data-src','data-original','data-lazy-src'):
            if node.get(attr): imgs.append(canonical(url,node[attr]))
        for attr in ('srcset','data-srcset'):
            if node.get(attr):
                for part in node[attr].split(','):
                    if part.strip(): imgs.append(canonical(url,part.strip().split()[0]))
    for node in soup.select('meta[property="og:image"], meta[name="twitter:image"]'):
        if node.get('content'): imgs.append(canonical(url,node['content']))
    for node in soup(['script','style','template','noscript']): node.decompose()
    return title, codes(soup.get_text(' ',strip=True)), set(filter(None,links)), set(filter(None,imgs))

class Crawler:
    def __init__(self,args):
        self.a=args; self.db=sqlite3.connect(args.db)
        self.db.executescript('''CREATE TABLE IF NOT EXISTS queue(url TEXT, kind TEXT, state TEXT DEFAULT 'pending', error TEXT, PRIMARY KEY(url,kind));
        CREATE TABLE IF NOT EXISTS sources(image TEXT, page TEXT, PRIMARY KEY(image,page));
        CREATE TABLE IF NOT EXISTS images(sha TEXT PRIMARY KEY, findings TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS results(url TEXT, code TEXT, kind TEXT, payload TEXT, PRIMARY KEY(url,code,kind));''')
        self.session=requests.Session(); self.session.headers['User-Agent']=UA
        self.robots={}; self.last=0; self.pagehost=urlsplit(args.start).hostname
        self.imagehosts=set(args.image_host or [])|{self.pagehost}
        self.enqueue(args.start,'page')
        if args.sitemap: self.enqueue(args.sitemap,'sitemap')
        with self.db: self.db.execute("UPDATE queue SET state='pending' WHERE state='running'")
    def scoped(self,url,kind):
        if not url: return False
        p=urlsplit(url)
        return p.hostname in (self.imagehosts if kind=='image' else {self.pagehost}) and p.scheme=='https'
    def enqueue(self,url,kind,source=None):
        if not self.scoped(url,kind): return
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO queue(url,kind) VALUES (?,?)',(url,kind))
            if source: self.db.execute('INSERT OR IGNORE INTO sources VALUES (?,?)',(url,source))
    def request(self,url,delay):
        time.sleep(max(0,delay-(time.monotonic()-self.last)))
        self.last=time.monotonic()
        with self.session.get(url,timeout=(10,25),stream=True,allow_redirects=False) as r:
            if r.status_code in (429,503): raise RuntimeError(f'HTTP {r.status_code}: stopped; respect Retry-After={r.headers.get("Retry-After", "unspecified")}')
            if r.status_code != 200: raise ValueError(f'HTTP {r.status_code}; redirects not followed')
            data=bytearray()
            for chunk in r.iter_content(65536):
                data.extend(chunk)
                if len(data)>MAX_BYTES: raise ValueError('response exceeds size cap')
            return bytes(data), r.headers.get('Content-Type','').lower()
    def fetch(self,url):
        p=urlsplit(url); root=f'{p.scheme}://{p.netloc}'
        if root not in self.robots:
            from protego import Protego
            try:
                body,_=self.request(root+'/robots.txt',self.a.delay)
                self.robots[root]=Protego.parse(body.decode('utf-8',errors='replace'))
            except ValueError: self.robots[root]=None
        rp=self.robots[root]
        if rp is None or not rp.can_fetch(url,UA): raise PermissionError('robots.txt unavailable or disallows URL')
        delay=max(self.a.delay,rp.crawl_delay(UA) or 0)
        rate=rp.request_rate(UA)
        if rate and rate.requests: delay=max(delay,rate.seconds/rate.requests)
        return self.request(url,delay)
    def hit(self,url,code,kind,**kw):
        item=dict(code=code,url=url,kind=kind,detected_at=utc_now(),validity='unverified',**kw)
        with self.db:
            cur=self.db.execute('INSERT OR IGNORE INTO results VALUES (?,?,?,?)',(url,code,kind,json.dumps(item,ensure_ascii=False)))
        if cur.rowcount: print(json.dumps(item,ensure_ascii=False),flush=True)
    def process(self,url,kind):
        data,ctype=self.fetch(url)
        if kind=='sitemap':
            if data.startswith(b'\x1f\x8b'): raise ValueError('compressed sitemap not supported')
            root=ET.fromstring(data)
            nextkind='sitemap' if root.tag.split('}')[-1]=='sitemapindex' else 'page'
            for child in root:
                loc=next((n.text for n in child if n.tag.split('}')[-1]=='loc'),None)
                if loc: self.enqueue(canonical(url,loc),nextkind)
        elif kind=='page':
            if 'html' not in ctype: raise ValueError('not HTML')
            title,found,links,imgs=html_items(url,data)
            for code in found: self.hit(url,code,'text',title=title)
            for img in sorted(imgs): self.enqueue(img,'image',url)
            for link in sorted(links): self.enqueue(link,'page')
        else:
            if not ctype.startswith('image/'): raise ValueError('not image')
            sha=hashlib.sha256(data).hexdigest()
            row=self.db.execute('SELECT findings FROM images WHERE sha=?',(sha,)).fetchone()
            if row: hits=json.loads(row[0])
            else:
                with tempfile.NamedTemporaryFile(suffix='.img') as f:
                    f.write(data); f.flush(); hits=inspect(f.name)
                with self.db: self.db.execute('INSERT OR IGNORE INTO images VALUES (?,?)',(sha,json.dumps(hits)))
            for h in hits:
                h=dict(h); code=h.pop('code'); self.hit(url,code,'image',sha256=sha,**h)
    def run(self):
        for i in range(self.a.max_items):
            row=self.db.execute("SELECT url,kind FROM queue WHERE state='pending' ORDER BY CASE kind WHEN 'image' THEN 0 WHEN 'sitemap' THEN 1 ELSE 2 END,rowid LIMIT 1").fetchone()
            if not row: break
            url,kind=row
            with self.db: self.db.execute("UPDATE queue SET state='running' WHERE url=? AND kind=?",row)
            state,error='done',None
            try: self.process(url,kind)
            except PermissionError as exc: state,error='blocked',str(exc)
            except (RuntimeError,requests.RequestException) as exc:
                with self.db: self.db.execute("UPDATE queue SET state='pending',error=? WHERE url=? AND kind=?",(str(exc),*row))
                print(f'STOP: {exc}',file=sys.stderr); break
            except Exception as exc: state,error='error',str(exc)
            with self.db: self.db.execute('UPDATE queue SET state=?,error=? WHERE url=? AND kind=?',(state,error,*row))
            print(f'{i+1}/{self.a.max_items} {state} {kind} {url}',file=sys.stderr,flush=True)
        with open(self.a.report,'w',encoding='utf-8') as f:
            for url,kind,payload in self.db.execute('SELECT url,kind,payload FROM results ORDER BY rowid'):
                item=json.loads(payload)
                if kind=='image': item['source_pages']=[r[0] for r in self.db.execute('SELECT page FROM sources WHERE image=?',(url,))]
                f.write(json.dumps(item,ensure_ascii=False)+'\n')
        print(dict(self.db.execute('SELECT state,count(*) FROM queue GROUP BY state')),file=sys.stderr)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--start',required=True); p.add_argument('--sitemap'); p.add_argument('--image-host',action='append'); p.add_argument('--permission-confirmed',action='store_true'); p.add_argument('--delay',type=float,default=3); p.add_argument('--max-items',type=int,default=100); p.add_argument('--db',default='crawl.sqlite3'); p.add_argument('--report',default='results.jsonl')
    a=p.parse_args(); a.start=canonical(a.start,a.start)
    if not a.permission_confirmed: p.error('Confirm website and campaign permission before crawling.')
    if not a.start or urlsplit(a.start).scheme!='https' or a.delay<3 or not 1<=a.max_items<=500: p.error('HTTPS start, delay >=3 and 1..500 items required')
    if a.sitemap: a.sitemap=canonical(a.start,a.sitemap)
    Crawler(a).run()
if __name__=='__main__': main()
