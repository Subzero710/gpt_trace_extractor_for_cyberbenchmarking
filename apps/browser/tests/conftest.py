import contextlib,http.server,os,shutil,threading,pytest,pytest_asyncio
from browser_mcp.core import BrowserPolicy,BrowserRuntimeV2
HTML=b'''<title>v2</title><input id="text"><select id="sel"><option value="a">A</option><option value="b">B</option></select><input id="file" type="file"><button id="btn" onclick="console.log('clicked')">Click</button>'''
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):self.send_response(200);self.send_header('Content-Length',str(len(HTML)));self.end_headers();self.wfile.write(HTML)
 def log_message(self,*a):pass
@pytest_asyncio.fixture
async def browser_v2(tmp_path):
 if shutil.which('cloakserve') is None:pytest.skip('requires CloakBrowser image')
 h=http.server.ThreadingHTTPServer(('127.0.0.1',0),H);t=threading.Thread(target=h.serve_forever,daemon=True);t.start();r=BrowserRuntimeV2(tmp_path/'state',fingerprint_seed=123,search_url_template='https://duckduckgo.com/?q={query}',policy=BrowserPolicy({'127.0.0.1'}),browser_uid=os.getuid(),browser_gid=os.getgid(),humanize=False);i={'task_id':'t','environment_id':'e','task_fingerprint':'a'*64}
 try:await r.start();await r.prepare(i);u=f'http://127.0.0.1:{h.server_port}/';await r.call('navigate',{'url':u});yield r,u
 finally:
  with contextlib.suppress(Exception):await r.shutdown()
  h.shutdown();t.join()
