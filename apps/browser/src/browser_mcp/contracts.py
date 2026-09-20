from __future__ import annotations
import hashlib,json
from copy import deepcopy
from typing import Any,Literal
from pydantic import BaseModel,ConfigDict,Field
APP_ID='browser';VERSION='2.0.0';SCHEMA_VERSION=2
class M(BaseModel):model_config=ConfigDict(extra='forbid',strict=True)
class Empty(M):pass
class Page(M):page_id:str|None=None
class Reload(Page):wait_until:Literal['domcontentloaded','load']='domcontentloaded'
class New(M):url:str|None=None;context_id:str|None=None
class Switch(M):page_id:str
class Sel(M):selector:str
class Hover(Sel):timeout_ms:int=Field(15000,ge=1,le=60000)
class Drag(M):source_selector:str;target_selector:str
class Select(Sel):values:list[str]=Field(min_length=1)
class Upload(Sel):filename:str;content_base64:str;mime_type:str|None=None
class Down(Sel):max_bytes:int=Field(10485760,ge=1,le=67108864)
class Inspect(M):selector:str='html';max_nodes:int=Field(1000,ge=1,le=10000);max_chars:int=Field(200000,ge=1,le=2000000)
class Html(M):selector:str|None=None;max_chars:int=Field(1000000,ge=1,le=5000000)
class Attr(Sel):name:str
class Eval(M):expression:str;argument:Any=None
class Cookies(M):urls:list[str]=Field(default_factory=list)
class Cookie(M):name:str;value:str;url:str|None=None;domain:str|None=None;path:str='/';expires:float|None=None;http_only:bool=False;secure:bool=False;same_site:Literal['Strict','Lax','None']='Lax'
class State(M):content_base64:str
class Ctx(M):user_agent:str|None=None;locale:str|None=None;timezone_id:str|None=None;viewport_width:int=1280;viewport_height:int=720
class CtxId(M):context_id:str
class Logs(M):limit:int=Field(200,ge=1,le=5000);clear:bool=False
class Req(M):request_id:str
class Resp(Req):max_bytes:int=Field(10485760,ge=1,le=67108864)
class Trace(M):action:Literal['start','stop'];screenshots:bool=True;snapshots:bool=True;sources:bool=False;max_bytes:int=33554432
class UA(M):user_agent:str
class VP(M):width:int=Field(ge=320,le=7680);height:int=Field(ge=240,le=4320)
class TZ(M):timezone_id:str
class Geo(M):latitude:float=Field(ge=-90,le=90);longitude:float=Field(ge=-180,le=180);accuracy:float=Field(0,ge=0)
class Out(M):model_config=ConfigDict(extra='allow',strict=True)
MODELS={'go_back':(Page,Out),'go_forward':(Page,Out),'reload':(Reload,Out),'new_page':(New,Out),'close_page':(Page,Out),'switch_page':(Switch,Out),'hover':(Hover,Out),'drag':(Drag,Out),'select_option':(Select,Out),'upload_file':(Upload,Out),'download_file':(Down,Out),'inspect_dom':(Inspect,Out),'query_selector':(Sel,Out),'get_html':(Html,Out),'get_attribute':(Attr,Out),'evaluate_javascript':(Eval,Out),'get_cookies':(Cookies,Out),'set_cookie':(Cookie,Out),'clear_cookies':(Empty,Out),'export_storage_state':(Empty,Out),'import_storage_state':(State,Out),'create_context':(Ctx,Out),'destroy_context':(CtxId,Out),'get_console_logs':(Logs,Out),'get_network_logs':(Logs,Out),'get_request_details':(Req,Out),'get_response_body':(Resp,Out),'performance_trace':(Trace,Out),'set_user_agent':(UA,Out),'set_viewport':(VP,Out),'set_timezone':(TZ,Out),'set_geolocation':(Geo,Out)}
def t(n,d,c,i,o={'type':'object','additionalProperties':True}):return {'name':n,'description':d,'category':c,'inputSchema':i,'outputSchema':o}
OLD=(t('search','Search the public web.','navigation',{'type':'object','additionalProperties':True,'properties':{'query':{'type':'string'}},'required':['query']}),t('navigate','Navigate active tab.','navigation',{'type':'object','additionalProperties':True,'properties':{'url':{'type':'string'}},'required':['url']}),t('read_page','Read page text and refs.','dom',{'type':'object','additionalProperties':True}),t('click','Click element ref.','interaction',{'type':'object','additionalProperties':True}),t('type','Type into element ref.','interaction',{'type':'object','additionalProperties':True}),t('press','Press a key.','interaction',{'type':'object','additionalProperties':True}),t('wait','Wait.','interaction',{'type':'object','additionalProperties':True}),t('screenshot','Capture screenshot.','dom',{'type':'object','additionalProperties':True}),t('download','Download by element ref.','interaction',{'type':'object','additionalProperties':True}),t('tabs','Manage tabs.','navigation',{'type':'object','additionalProperties':True}))
def cat(n):
 if n in {'go_back','go_forward','reload','new_page','close_page','switch_page'}:return 'navigation'
 if n in {'hover','drag','select_option','upload_file','download_file'}:return 'interaction'
 if n in {'inspect_dom','query_selector','get_html','get_attribute','evaluate_javascript'}:return 'dom'
 if n in {'get_cookies','set_cookie','clear_cookies','export_storage_state','import_storage_state'}:return 'storage'
 if 'context' in n:return 'contexts'
 if n.startswith('set_'):return 'device'
 return 'network'
TOOLS=OLD+tuple(t(n,n.replace('_',' ').capitalize()+'.',cat(n),a.model_json_schema(),b.model_json_schema()) for n,(a,b) in MODELS.items())
def manifest():return {'schema_version':2,'app_id':APP_ID,'version':VERSION,'tools':deepcopy(list(TOOLS))}
def canonical_bytes(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def manifest_sha256():return hashlib.sha256(canonical_bytes(manifest())).hexdigest()
