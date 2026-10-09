"""TraceBack local evidence server and Vercel API, using SQLite or PostgreSQL."""
from __future__ import annotations
import csv, datetime as dt, html, io, json, os, re, sqlite3, urllib.parse, uuid
from collections import Counter, defaultdict
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get('TRACEBACK_DB', ROOT / 'traceback.db'))
MAX_UPLOAD = 10 * 1024 * 1024

def database_url():
    return os.environ.get('DATABASE_URL') or os.environ.get('POSTGRES_URL') or os.environ.get('POSTGRES_PRISMA_URL')

class Row(dict):
    """Mapping row that also preserves sqlite-style numeric indexing."""
    def __getitem__(self, key):
        if isinstance(key, int): return tuple(self.values())[key]
        return super().__getitem__(key)

class Cursor:
    def __init__(self, cursor): self.cursor=cursor
    def fetchone(self):
        row=self.cursor.fetchone()
        return Row(row) if row is not None and isinstance(row, dict) else row
    def fetchall(self):
        rows=self.cursor.fetchall()
        return [Row(r) if isinstance(r,dict) else r for r in rows]
    def __iter__(self): return iter(self.fetchall())

class Postgres:
    def __init__(self, conn): self.conn=conn
    def execute(self, sql, args=()):
        ignored='INSERT OR IGNORE INTO' in sql.upper()
        sql=sql.replace('INSERT OR IGNORE INTO','INSERT INTO')
        if ignored: sql += ' ON CONFLICT DO NOTHING'
        sql=sql.replace('?', '%s')
        return Cursor(self.conn.execute(sql, args))
    def executescript(self, sql):
        for statement in sql.split(';'):
            if statement.strip(): self.execute(statement)
    def commit(self): self.conn.commit()
    def rollback(self): self.conn.rollback()
    def close(self): self.conn.close()

@contextmanager
def connect():
    url=database_url()
    if os.environ.get('VERCEL') and not url:
        raise RuntimeError('Deployment is missing a hosted PostgreSQL connection string.')
    if url:
        import psycopg
        from psycopg.rows import dict_row
        db=Postgres(psycopg.connect(url, row_factory=dict_row))
    else:
        db=sqlite3.connect(DB); db.row_factory=sqlite3.Row; db.execute('PRAGMA foreign_keys=ON')
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback(); raise
    finally: db.close()

def normalize_time(value):
    if isinstance(value,(int,float)): return dt.datetime.fromtimestamp(value,dt.timezone.utc).isoformat().replace('+00:00','Z')
    text=str(value or '').strip()
    if not text: raise ValueError('timestamp is required')
    parsed=dt.datetime.fromisoformat(text.replace('Z','+00:00'))
    if parsed.tzinfo is None: parsed=parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat().replace('+00:00','Z')

def normalize(raw, source='import'):
    aliases={'timestamp':['timestamp','time','ts','datetime'],'src_ip':['src_ip','source_ip','src','source'],'dst_ip':['dst_ip','destination_ip','dst','destination'], 'src_port':['src_port','source_port'],'dst_port':['dst_port','destination_port'],'protocol':['protocol','proto'],'event_type':['event_type','type'],'length':['length','packet_length','bytes'],'severity':['severity']}
    item={}
    for target,keys in aliases.items():
        item[target]=next((raw[k] for k in keys if k in raw and raw[k] not in ('',None)),None)
    for key in ('src_ip','dst_ip'):
        if not item[key] or len(str(item[key]))>64: raise ValueError(key+' is required or invalid')
    item['timestamp']=normalize_time(item['timestamp'])
    for k in ('src_port','dst_port','length'):
        if item[k] is not None:
            item[k]=int(item[k]); limit=65535 if 'port' in k else 100_000_000
            if not 0<=item[k]<=limit: raise ValueError(k+' outside valid range')
    item['protocol']=str(item['protocol'] or 'unknown').upper()[:24]
    item['event_type']=str(item['event_type'] or 'connection')[:80]
    item['severity']=str(item['severity'] or 'info').lower()[:20]
    item['source_ref']=str(raw.get('source_ref') or source)[:200]
    item['packet_index']=raw.get('packet_index')
    return item

def init_db():
    with connect() as d:
        d.executescript('''CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,title TEXT,severity TEXT,status TEXT,created TEXT,notes TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,incident_id TEXT,timestamp TEXT,src_ip TEXT,dst_ip TEXT,src_port INTEGER,dst_port INTEGER,protocol TEXT,event_type TEXT,length INTEGER,severity TEXT,source_ref TEXT,packet_index INTEGER,FOREIGN KEY(incident_id) REFERENCES incidents(id));
        CREATE INDEX IF NOT EXISTS event_time ON events(timestamp); CREATE INDEX IF NOT EXISTS event_incident ON events(incident_id);''')
        if d.execute('SELECT count(*) FROM events').fetchone()[0]==0: seed(d)

def seed(d):
    if d.execute("SELECT 1 FROM events WHERE id='demo-001'").fetchone(): return
    iid='inc-demo-001'; d.execute('INSERT OR IGNORE INTO incidents VALUES(?,?,?,?,?,?)',(iid,'Unusual service discovery sequence','high','open','2026-10-08T08:00:00Z','Synthetic training data. Repeated connections from the test workstation warrant review; evidence alone does not establish malicious intent.'))
    base=dt.datetime(2026,10,8,8,14,tzinfo=dt.timezone.utc)
    rows=[('10.20.4.18','10.20.4.1',53,'DNS','dns query'),('10.20.4.18','10.20.4.1',53,'DNS','dns response'),('10.20.4.18','10.20.4.22',22,'TCP','connection attempt'),('10.20.4.18','10.20.4.22',443,'TCP','connection attempt'),('10.20.4.18','10.20.4.22',3389,'TCP','connection attempt'),('10.20.4.18','10.20.4.31',22,'TCP','connection attempt'),('10.20.4.18','10.20.4.31',445,'TCP','connection attempt'),('10.20.4.18','10.20.4.31',8080,'TCP','connection attempt'),('10.20.4.22','203.0.113.44',443,'TCP','outbound connection'),('10.20.4.18','203.0.113.44',443,'TCP','outbound connection'),('10.20.4.31','10.20.4.1',53,'DNS','dns query'),('10.20.4.18','10.20.4.22',3389,'TCP','connection attempt')]
    for i,(src,dst,port,proto,typ) in enumerate(rows):
        e=normalize({'timestamp':(base+dt.timedelta(seconds=i*19)).isoformat(),'src_ip':src,'dst_ip':dst,'src_port':49100+i,'dst_port':port,'protocol':proto,'event_type':typ,'length':78+i*11,'severity':'medium' if typ=='connection attempt' else 'info','source_ref':'synthetic-training-fixture','packet_index':i+1})
        d.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(f'demo-{i+1:03}',iid,*[e[k] for k in ('timestamp','src_ip','dst_ip','src_port','dst_port','protocol','event_type','length','severity','source_ref','packet_index')]))

def obj(row): return dict(row)
def events(incident=None, q=''):
    with connect() as d:
        sql='SELECT * FROM events'; args=[]; cond=[]
        if incident: cond.append('incident_id=?');args.append(incident)
        if q: cond.append('(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ? OR event_type LIKE ?)'); args += [f'%{q}%']*4
        if cond: sql+=' WHERE '+' AND '.join(cond)
        sql+=' ORDER BY timestamp,id'; return [obj(x) for x in d.execute(sql,args)]
def incidents():
    with connect() as d: return [dict(r)|{'event_count':d.execute('select count(*) from events where incident_id=?',(r['id'],)).fetchone()[0]} for r in d.execute('select * from incidents order by created desc')]
def findings(inc=None):
    out=[]
    for incident in incidents():
        if inc and incident['id']!=inc: continue
        ev=events(incident['id']); ports=defaultdict(set); refs=defaultdict(list)
        for e in ev:
            if e['protocol']=='TCP' and e['dst_port'] is not None: ports[e['src_ip']].add(e['dst_port']);refs[e['src_ip']].append(e)
        for src,ps in ports.items():
            if len(ps)>=5:
                sup=refs[src]
                out.append({'id':'finding-scan-'+incident['id'],'incident_id':incident['id'],'title':'Possible TCP port scan','severity':'medium','confidence':'moderate','confidence_basis':f'{len(ps)} distinct TCP destination ports observed from one source in {len(sup)} records. Heuristic threshold: 5 ports.','explanation':f'{src} contacted {len(ps)} distinct TCP destination ports: '+', '.join(map(str,sorted(ps)))+'.','interpretation':'This pattern is consistent with service discovery. It does not establish malicious intent, successful access, or compromise.','rule':'tcp-port-fanout-v1','event_ids':[e['id'] for e in sup],'time_start':sup[0]['timestamp'],'time_end':sup[-1]['timestamp'],'limitations':'Based only on imported records; NAT, monitoring duplication, authorized scanning, and incomplete capture can affect interpretation.'})
    return out
def graph(inc):
    ev=events(inc); nodes={}; edges={}
    for e in ev:
        for ip,role in ((e['src_ip'],'source'),(e['dst_ip'],'destination')):
            external=not (ip.startswith(('10.','192.168.','172.16.')) or ip in ('127.0.0.1',))
            n=nodes.setdefault(ip,{'id':ip,'external':external,'kind':'external endpoint' if external else ('infrastructure' if ip.endswith('.1') else 'internal host'),'events':0});n['events']+=1
        key=(e['src_ip'],e['dst_ip'],e['protocol'],e['dst_port']); edges.setdefault(key,{'source':key[0],'target':key[1],'protocol':key[2],'port':key[3],'count':0,'suspicious':False})['count']+=1
        edges[key]['suspicious'] |= e['severity'] in ('high','critical','medium')
    return {'nodes':list(nodes.values()),'edges':list(edges.values()),'event_count':len(ev)}
def overview():
    its=incidents(); ev=events(); hosts={e['src_ip'] for e in ev}|{e['dst_ip'] for e in ev}
    return {'incidents':len(its),'critical_high':sum(i['severity'] in ('critical','high') for i in its),'hosts':len(hosts),'events':len(ev),'recent':its[:5],'demo':True,'storage':'PostgreSQL' if database_url() else 'SQLite'}

class Handler(BaseHTTPRequestHandler):
    server_version='TraceBack/0.1'
    def log_message(self,*args): pass
    def send(self,code,data,ctype='application/json; charset=utf-8'):
        raw=data if isinstance(data,bytes) else (json.dumps(data,ensure_ascii=False).encode() if ctype.startswith('application/json') else str(data).encode())
        self.send_response(code);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(raw)));self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:");self.end_headers();self.wfile.write(raw)
    def api_access(self):
        key=os.environ.get('TRACEBACK_ACCESS_KEY')
        if not key:
            if os.environ.get('VERCEL'):
                self.send(503,{'error':'Deployment is missing TRACEBACK_ACCESS_KEY.'});return False
            return True
        supplied=self.headers.get('Authorization','')
        import hmac
        if hmac.compare_digest(supplied, 'Bearer '+key): return True
        self.send(401,{'error':'Enter the workspace access key to continue.'});return False
    def do_GET(self):
        u=urllib.parse.urlparse(self.path); path=u.path
        if path=='/' or path=='/index.html': return self.send(200,(ROOT/'index.html').read_bytes(),'text/html; charset=utf-8')
        if path in ('/app.js','/style.css'): return self.send(200,(ROOT/path[1:]).read_bytes(),'text/javascript; charset=utf-8' if path.endswith('.js') else 'text/css; charset=utf-8')
        if path.startswith('/api/') and not self.api_access(): return
        if path=='/api/overview': return self.send(200,overview())
        if path=='/api/incidents': return self.send(200,{'items':incidents()})
        if path=='/api/events':
            q=urllib.parse.parse_qs(u.query); items=events(q.get('incident',[None])[0],q.get('q',[''])[0]); page=max(1,int(q.get('page',['1'])[0])); size=min(200,max(1,int(q.get('limit',['100'])[0])));return self.send(200,{'items':items[(page-1)*size:page*size],'total':len(items),'page':page,'limit':size})
        if path=='/api/findings': return self.send(200,{'items':findings(urllib.parse.parse_qs(u.query).get('incident',[None])[0])})
        if path=='/api/hosts': return self.send(200,{'items':graph(None)['nodes']})
        m=re.fullmatch(r'/api/incidents/([^/]+)(?:/(graph|report))?',path)
        if m:
            iid=m[1]; found=next((i for i in incidents() if i['id']==iid),None)
            if not found:return self.send(404,{'error':'Incident not found'})
            if m[2]=='graph': return self.send(200,graph(iid))
            if m[2]=='report': return self.report(found)
            return self.send(200,found|{'events':events(iid),'findings':findings(iid),'graph':graph(iid)})
        if path.startswith('/api/'): return self.send(404,{'error':'Not found'})
        return self.send(404,'Not found','text/plain')
    def report(self,incident):
        ev=events(incident['id']); fs=findings(incident['id']); rows=''.join('<tr>'+''.join(f'<td>{html.escape(str(e[k] or ""))}</td>' for k in ('timestamp','src_ip','dst_ip','dst_port','protocol','event_type','source_ref'))+'</tr>' for e in ev)
        fshtml=''.join(f'<section><h2>{html.escape(f["title"])}</h2><p>{html.escape(f["explanation"])}</p><p><b>Interpretation:</b> {html.escape(f["interpretation"])}</p><p><b>Evidence IDs:</b> {html.escape(", ".join(f["event_ids"]))}</p><p>{html.escape(f["limitations"])}</p></section>' for f in fs) or '<p>No derived findings.</p>'
        doc=f'<!doctype html><meta charset="utf-8"><title>TraceBack report</title><style>body{{font:15px system-ui;max-width:1100px;margin:40px auto;color:#17212f}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccd3dc;padding:7px;text-align:left}}th{{background:#eaf0f5}}code{{font-family:monospace}}</style><h1>Investigation report — {html.escape(incident["title"])}</h1><p>Generated {dt.datetime.now(dt.timezone.utc).isoformat()} · Investigation scope: {html.escape(incident["created"])} · {len(ev)} observed records</p><p><b>Status:</b> {html.escape(incident["status"])} · <b>Severity:</b> {html.escape(incident["severity"])}</p><h2>Analyst notes</h2><p>{html.escape(incident["notes"] or "None recorded")}</p><h2>Derived findings</h2>{fshtml}<h2>Observed event timeline</h2><table><tr>'+''.join(f'<th>{h}</th>' for h in ('Timestamp UTC','Source','Destination','Port','Protocol','Event type','Source reference'))+f'</tr>{rows}</table><p>Events are observations. Derived findings are heuristic and do not prove malicious intent or compromise. Analysis rule: tcp-port-fanout-v1.</p>'
        return self.send(200,doc,'text/html; charset=utf-8')
    def do_POST(self):
        path=urllib.parse.urlparse(self.path).path
        if path.startswith('/api/') and not self.api_access(): return
        if path=='/api/sample':
            with connect() as d: seed(d)
            return self.send(200,overview())
        if path!='/api/upload': return self.send(404,{'error':'Not found'})
        length=int(self.headers.get('Content-Length','0'))
        max_upload=4*1024*1024 if os.environ.get('VERCEL') else MAX_UPLOAD
        if length<=0 or length>max_upload: return self.send(413,{'error':f'Upload must be between 1 byte and {max_upload//(1024*1024)} MB'})
        body=self.rfile.read(length); boundary=re.search(r'boundary=(?:"([^"]+)"|([^;]+))',self.headers.get('Content-Type',''))
        if not boundary:return self.send(400,{'error':'Expected multipart form field named file'})
        b=(boundary[1] or boundary[2]).encode(); parts=body.split(b'--'+b); payload=None; filename='upload'
        for part in parts:
            head,sep,data=part.partition(b'\r\n\r\n')
            if sep and b'name="file"' in head:
                match=re.search(rb'filename="([^"]{1,200})"',head); filename=(match.group(1).decode('utf-8','replace') if match else 'upload');payload=data.rstrip(b'\r\n-');break
        if payload is None:return self.send(400,{'error':'Missing file field'})
        ext=Path(filename).suffix.lower()
        if ext not in ('.json','.jsonl','.ndjson','.csv'):return self.send(415,{'error':'Supported files: JSON, JSONL, CSV. PCAP is unavailable in this runtime.'})
        try:
            txt=payload.decode('utf-8-sig'); raw=json.loads(txt) if ext=='.json' else ([json.loads(line) for line in txt.splitlines() if line.strip()] if ext in ('.jsonl','.ndjson') else list(csv.DictReader(io.StringIO(txt))))
            if isinstance(raw,dict):raw=raw.get('events',[])
            if not isinstance(raw,list):raise ValueError('JSON must be an event list or an object containing events')
        except Exception as e:return self.send(400,{'error':'Could not parse input: '+str(e)[:180]})
        accepted=[];rejected=[]
        for i,row in enumerate(raw,1):
            try:
                if not isinstance(row,dict):raise ValueError('record must be an object')
                accepted.append(normalize(row,f'{Path(filename).name}:row {i}'))
            except Exception as e:rejected.append({'row':i,'error':str(e)[:140]})
        if not accepted:return self.send(422,{'error':'No valid events found','accepted':0,'rejected':rejected[:40],'rejected_count':len(rejected)})
        iid='inc-'+uuid.uuid4().hex[:12]; title='Imported evidence · '+Path(filename).name[:100]; created=accepted[0]['timestamp'];
        with connect() as d:
            d.execute('INSERT INTO incidents VALUES(?,?,?,?,?,?)',(iid,title,'medium' if len(accepted)>=5 else 'informational','open',created,f'Imported evidence. {len(accepted)} accepted, {len(rejected)} rejected.'))
            for e in accepted:d.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(uuid.uuid4().hex,iid,*[e[k] for k in ('timestamp','src_ip','dst_ip','src_port','dst_port','protocol','event_type','length','severity','source_ref','packet_index')]))
        return self.send(201,{'incident_id':iid,'accepted':len(accepted),'rejected_count':len(rejected),'rejected':rejected[:40],'incident':next(i for i in incidents() if i['id']==iid)})

if __name__=='__main__':
    init_db(); host=os.environ.get('TRACEBACK_HOST','127.0.0.1'); port=int(os.environ.get('TRACEBACK_PORT','8765'))
    print(f'TraceBack listening on http://{host}:{port} · database {DB}')
    ThreadingHTTPServer((host,port),Handler).serve_forever()
