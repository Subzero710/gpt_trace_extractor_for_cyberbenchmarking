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
class PageInfo(M):page_id:str;context_id:str;url:str;title:str
class OkPage(PageInfo):ok:bool=True;filename:str|None=None;mime_type:str|None=None
class CloseOut(M):active_page_id:str|None;pages:list[PageInfo]
class DownloadOut(M):filename:str;size:int;sha256:str;content_base64:str
class InspectOut(M):selector:str;nodes:list[dict[str,Any]];truncated:bool
class QueryOut(M):selector:str;count:int;matches:list[dict[str,Any]]
class HtmlOut(M):html:str;truncated:bool
class AttrOut(M):selector:str;name:str;value:str|None
class EvalOut(M):result:Any
class CookiesOut(M):cookies:list[dict[str,Any]]
class StateOut(M):content_base64:str;size:int;sha256:str
class ContextOut(M):context_id:str;active:bool;page_id:str|None
class DeviceOut(M):ok:bool;settings:dict[str,Any]
class LogsOut(M):entries:list[dict[str,Any]]
class RequestOut(M):request:dict[str,Any]
class BodyOut(M):request_id:str;mime_type:str|None;size:int;sha256:str;content_base64:str;truncated:bool
class TraceOut(M):action:Literal['start','stop'];active:bool;size:int|None=None;sha256:str|None=None;content_base64:str|None=None
MODELS={'go_back':(Page,PageInfo),'go_forward':(Page,PageInfo),'reload':(Reload,PageInfo),'new_page':(New,PageInfo),'close_page':(Page,CloseOut),'switch_page':(Switch,PageInfo),'hover':(Hover,OkPage),'drag':(Drag,OkPage),'select_option':(Select,OkPage),'upload_file':(Upload,OkPage),'download_file':(Down,DownloadOut),'inspect_dom':(Inspect,InspectOut),'query_selector':(Sel,QueryOut),'get_html':(Html,HtmlOut),'get_attribute':(Attr,AttrOut),'evaluate_javascript':(Eval,EvalOut),'get_cookies':(Cookies,CookiesOut),'set_cookie':(Cookie,CookiesOut),'clear_cookies':(Empty,CookiesOut),'export_storage_state':(Empty,StateOut),'import_storage_state':(State,StateOut),'create_context':(Ctx,ContextOut),'destroy_context':(CtxId,ContextOut),'get_console_logs':(Logs,LogsOut),'get_network_logs':(Logs,LogsOut),'get_request_details':(Req,RequestOut),'get_response_body':(Resp,BodyOut),'performance_trace':(Trace,TraceOut),'set_user_agent':(UA,DeviceOut),'set_viewport':(VP,DeviceOut),'set_timezone':(TZ,DeviceOut),'set_geolocation':(Geo,DeviceOut)}
def t(n,d,c,i,o):return {'name':n,'description':d,'category':c,'inputSchema':i,'outputSchema':o}
OLD=({'description': 'Search the public web through the isolated task browser and return ordered result links.', 'inputSchema': {'additionalProperties': False, 'properties': {'max_results': {'default': 10, 'maximum': 20, 'minimum': 1, 'type': 'integer'}, 'query': {'minLength': 1, 'type': 'string'}}, 'required': ['query'], 'type': 'object'}, 'name': 'search', 'category': 'navigation', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Navigate the active browser tab to an HTTP or HTTPS URL allowed by the network policy.', 'inputSchema': {'additionalProperties': False, 'properties': {'url': {'minLength': 1, 'type': 'string'}, 'wait_until': {'default': 'domcontentloaded', 'enum': ['domcontentloaded', 'load'], 'type': 'string'}}, 'required': ['url'], 'type': 'object'}, 'name': 'navigate', 'category': 'navigation', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Read visible text and interactive element references from the active browser tab.', 'inputSchema': {'additionalProperties': False, 'properties': {'include_elements': {'default': True, 'type': 'boolean'}, 'max_chars': {'default': 50000, 'maximum': 200000, 'minimum': 1, 'type': 'integer'}, 'max_elements': {'default': 200, 'maximum': 500, 'minimum': 1, 'type': 'integer'}}, 'type': 'object'}, 'name': 'read_page', 'category': 'dom', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Click an element reference returned by read_page in the active tab.', 'inputSchema': {'additionalProperties': False, 'properties': {'ref': {'pattern': '^e[1-9][0-9]*$', 'type': 'string'}}, 'required': ['ref'], 'type': 'object'}, 'name': 'click', 'category': 'interaction', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Enter text into an editable element reference and optionally submit with Enter.', 'inputSchema': {'additionalProperties': False, 'properties': {'clear': {'default': True, 'type': 'boolean'}, 'ref': {'pattern': '^e[1-9][0-9]*$', 'type': 'string'}, 'submit': {'default': False, 'type': 'boolean'}, 'text': {'type': 'string'}}, 'required': ['ref', 'text'], 'type': 'object'}, 'name': 'type', 'category': 'interaction', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Press one allowed navigation or editing key in the active tab or on a referenced element.', 'inputSchema': {'additionalProperties': False, 'properties': {'key': {'enum': ['Enter', 'Escape', 'Tab', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'PageUp', 'PageDown', 'Home', 'End', 'Backspace', 'Delete'], 'type': 'string'}, 'ref': {'default': None, 'pattern': '^e[1-9][0-9]*$', 'type': ['string', 'null']}}, 'required': ['key'], 'type': 'object'}, 'name': 'press', 'category': 'interaction', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Wait for a bounded duration or until exact visible text appears in the active tab.', 'inputSchema': {'additionalProperties': False, 'properties': {'seconds': {'default': 1, 'maximum': 30, 'minimum': 0, 'type': 'number'}, 'text': {'default': None, 'type': ['string', 'null']}}, 'type': 'object'}, 'name': 'wait', 'category': 'interaction', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Capture a PNG screenshot of the active tab and return bounded base64 content.', 'inputSchema': {'additionalProperties': False, 'properties': {'full_page': {'default': False, 'type': 'boolean'}}, 'type': 'object'}, 'name': 'screenshot', 'category': 'dom', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Click a referenced download control and return a bounded downloaded file as base64 with integrity metadata.', 'inputSchema': {'additionalProperties': False, 'properties': {'max_bytes': {'default': 5242880, 'maximum': 10485760, 'minimum': 1, 'type': 'integer'}, 'ref': {'pattern': '^e[1-9][0-9]*$', 'type': 'string'}}, 'required': ['ref'], 'type': 'object'}, 'name': 'download', 'category': 'interaction', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'List, create, select, or close tabs in the isolated task browser.', 'inputSchema': {'additionalProperties': False, 'properties': {'action': {'default': 'list', 'enum': ['list', 'new', 'select', 'close'], 'type': 'string'}, 'index': {'default': None, 'minimum': 0, 'type': ['integer', 'null']}, 'url': {'default': None, 'type': ['string', 'null']}}, 'type': 'object'}, 'name': 'tabs', 'category': 'navigation', 'outputSchema': {'type': 'object', 'additionalProperties': True}})
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
