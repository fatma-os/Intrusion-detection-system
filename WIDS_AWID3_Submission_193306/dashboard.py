"""AIRGUARD local web dashboard. Binds only to 127.0.0.1; capture is receive-only."""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parent
HTML=ROOT/'dashboard.html'
METRICS=ROOT/'metrics.json'
ALERTS=ROOT/'alerts.jsonl'
CAPTURE_LOCK=threading.RLock()
CAPTURE_PROCESS: subprocess.Popen|None=None
CAPTURE_STARTED: str|None=None

def read_alerts(limit=50):
    if not ALERTS.exists(): return []
    try: lines=ALERTS.read_text(encoding='utf-8').splitlines()[-limit:]
    except OSError: return []
    events=[]
    for line in reversed(lines):
        try:
            event=json.loads(line)
            if isinstance(event,dict): events.append(event)
        except json.JSONDecodeError: continue
    return events

def capture_status():
    with CAPTURE_LOCK:
        running=CAPTURE_PROCESS is not None and CAPTURE_PROCESS.poll() is None
        return {'running':running,'started_at':CAPTURE_STARTED,
                'return_code':None if running or CAPTURE_PROCESS is None else CAPTURE_PROCESS.returncode}

class Handler(BaseHTTPRequestHandler):
    server_version='AIRGUARDLocal/1.0'
    def log_message(self,fmt,*args):
        if args and str(args[1]).startswith('5'): super().log_message(fmt,*args)
    def local_client(self):
        host=urlsplit('//'+self.headers.get('Host','')).hostname
        if host not in {'127.0.0.1','localhost'}: return False
        origin=self.headers.get('Origin')
        return not origin or urlsplit(origin).hostname in {'127.0.0.1','localhost'}
    def send_json(self,code,payload):
        body=json.dumps(payload).encode('utf-8')
        self.send_response(code);self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store')
        self.end_headers();self.wfile.write(body)
    def do_GET(self):
        if not self.local_client(): self.send_error(403,'Local browser access only');return
        path=urlsplit(self.path).path
        if path=='/':
            try: body=HTML.read_bytes()
            except OSError: self.send_error(500,'dashboard.html is missing');return
            self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store')
            self.end_headers();self.wfile.write(body);return
        if path=='/api/status':
            try: metrics=json.loads(METRICS.read_text(encoding='utf-8'))
            except (OSError,json.JSONDecodeError) as exc: self.send_json(500,{'error':f'Could not read metrics.json: {exc}'});return
            self.send_json(200,{'metrics':metrics,'alerts':read_alerts(),'capture':capture_status()});return
        if path=='/favicon.ico': self.send_response(204);self.end_headers();return
        self.send_error(404,'Not found')
    def read_body(self):
        length=int(self.headers.get('Content-Length','0'))
        if length<0 or length>4096: raise ValueError('Request too large')
        return json.loads(self.rfile.read(length) or b'{}')
    def do_POST(self):
        global CAPTURE_PROCESS,CAPTURE_STARTED
        if not self.local_client(): self.send_error(403,'Local browser access only');return
        path=urlsplit(self.path).path
        try: data=self.read_body()
        except (ValueError,json.JSONDecodeError) as exc: self.send_json(400,{'error':str(exc)});return
        if path=='/api/replay':
            try:
                result=subprocess.run([sys.executable,str(ROOT/'wids.py'),'replay'],cwd=ROOT,capture_output=True,text=True,timeout=60,check=False)
                self.send_json(200 if result.returncode==0 else 500,{'return_code':result.returncode,'output':(result.stdout+result.stderr).strip(),'alerts':read_alerts()})
            except subprocess.TimeoutExpired: self.send_json(504,{'error':'Replay took too long and was stopped.'})
            return
        if path=='/api/capture/start':
            interface=str(data.get('interface','')).strip()
            try: seconds=int(data.get('seconds',60))
            except (TypeError,ValueError): seconds=0
            if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',interface): self.send_json(400,{'error':'Enter a valid interface name (letters, numbers, _, ., : or -).'});return
            if not 5<=seconds<=3600: self.send_json(400,{'error':'Capture duration must be from 5 to 3600 seconds.'});return
            with CAPTURE_LOCK:
                if CAPTURE_PROCESS is not None and CAPTURE_PROCESS.poll() is None: self.send_json(409,{'error':'A capture is already running.'});return
                try:
                    CAPTURE_PROCESS=subprocess.Popen([sys.executable,str(ROOT/'wids.py'),'capture','--interface',interface,'--seconds',str(seconds)],cwd=ROOT)
                    CAPTURE_STARTED=datetime.now(timezone.utc).isoformat()
                except OSError as exc: self.send_json(500,{'error':f'Could not start capture: {exc}'});return
            self.send_json(200,{'message':f'Receive-only capture started on {interface} for {seconds} seconds.','capture':capture_status()});return
        if path=='/api/capture/stop':
            with CAPTURE_LOCK:
                proc=CAPTURE_PROCESS
                if proc is None or proc.poll() is not None: self.send_json(200,{'message':'No capture is currently running.','capture':capture_status()});return
                proc.terminate()
            self.send_json(200,{'message':'Capture stopped. Alerts already written remain in history.','capture':capture_status()});return
        self.send_error(404,'Not found')

def main():
    parser=argparse.ArgumentParser(description='Run AIRGUARD on this computer only.')
    parser.add_argument('--port',type=int,default=8765);parser.add_argument('--no-browser',action='store_true')
    args=parser.parse_args()
    if not 1024<=args.port<=65535: parser.error('Port must be between 1024 and 65535')
    try: server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    except OSError as exc: raise SystemExit(f'Could not start on localhost:{args.port}: {exc}. Close the other app or choose --port.')
    url=f'http://127.0.0.1:{args.port}/'
    print(f'AIRGUARD is running at {url}');print('Local computer only. Press Ctrl+C here to stop.')
    if not args.no_browser: webbrowser.open(url)
    try: server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt: print('\nStopping AIRGUARD...')
    finally:
        with CAPTURE_LOCK:
            if CAPTURE_PROCESS is not None and CAPTURE_PROCESS.poll() is None: CAPTURE_PROCESS.terminate()
        server.server_close()

if __name__=='__main__': main()

