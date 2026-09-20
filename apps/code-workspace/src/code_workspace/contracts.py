from __future__ import annotations
import hashlib,json
from copy import deepcopy
from typing import Any,Literal
from pydantic import BaseModel,ConfigDict,Field
APP_ID='code-workspace';VERSION='2.0.0';SCHEMA_VERSION=2
class M(BaseModel):model_config=ConfigDict(extra='forbid',strict=True)
class Empty(M):pass
class PathIn(M):path:str=Field(min_length=1)
class DelDir(PathIn):recursive:bool=False
class Move(M):source:str;destination:str;overwrite:bool=False
class Mk(PathIn):parents:bool=True;exist_ok:bool=True
class Tree(M):path:str='.';max_depth:int=Field(8,ge=0,le=64);max_entries:int=Field(2000,ge=1,le=10000)
class Find(M):path:str='.';name:str='*';type:Literal['any','file','directory']='any';max_results:int=Field(1000,ge=1,le=10000)
class TCreate(M):cwd:str='.';environment:dict[str,str]=Field(default_factory=dict)
class TSend(M):terminal_id:str;input:str
class TRead(M):terminal_id:str;max_bytes:int=Field(262144,ge=1,le=1048576);wait_seconds:float=Field(0,ge=0,le=30)
class TClose(M):terminal_id:str;force:bool=False
class Pid(M):pid:int=Field(ge=1)
class Kill(Pid):signal:Literal['TERM','KILL','INT','HUP']='TERM'
class EnvSet(M):values:dict[str,str]=Field(default_factory=dict);unset:list[str]=Field(default_factory=list)
class Venv(M):path:str='.venv';with_pip:bool=True
class Pip(M):packages:list[str]=Field(min_length=1);venv_path:str='.venv';upgrade:bool=False;timeout_seconds:int=Field(600,ge=1,le=1800)
class Py(M):path:str;args:list[str]=Field(default_factory=list);venv_path:str|None='.venv';cwd:str='.';timeout_seconds:int=Field(120,ge=1,le=1800)
class Apt(M):packages:list[str]=Field(min_length=1);update_index:bool=True;timeout_seconds:int=Field(900,ge=1,le=1800)
class Clone(M):repository:str;destination:str;branch:str|None=None;depth:int|None=Field(None,ge=1)
class GitCwd(M):cwd:str='.'
class Diff(GitCwd):staged:bool=False;pathspec:list[str]=Field(default_factory=list)
class Log(GitCwd):max_count:int=Field(20,ge=1,le=500)
class Branch(GitCwd):name:str|None=None;delete:bool=False
class Checkout(GitCwd):ref:str;create:bool=False
class Commit(GitCwd):message:str;all:bool=False;author_name:str='MCP Agent';author_email:str='mcp-agent@localhost'
class Http(M):url:str;method:Literal['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS']='GET';headers:dict[str,str]=Field(default_factory=dict);body:str|None=None;timeout_seconds:float=Field(30,gt=0,le=120);max_bytes:int=Field(1048576,ge=1,le=16777216)
class Download(M):url:str;path:str;timeout_seconds:float=Field(60,gt=0,le=300);max_bytes:int=Field(16777216,ge=1,le=16777216);overwrite:bool=False
class Dns(M):hostname:str;family:Literal['any','ipv4','ipv6']='any'
class Port(M):host:str;port:int=Field(ge=1,le=65535);timeout_seconds:float=Field(3,gt=0,le=30)
class Template(M):template_id:str|None=None
class Out(M):ok:bool=True;path:str|None=None;source:str|None=None;destination:str|None=None
class AnyOut(M):model_config=ConfigDict(extra='allow',strict=True)
MODELS={'workspace_delete_file':(PathIn,Out),'workspace_delete_directory':(DelDir,Out),'workspace_move':(Move,Out),'workspace_copy':(Move,Out),'workspace_create_directory':(Mk,Out),'workspace_stat':(PathIn,AnyOut),'workspace_tree':(Tree,AnyOut),'workspace_find':(Find,AnyOut),'create_terminal':(TCreate,AnyOut),'send_terminal_input':(TSend,AnyOut),'read_terminal_output':(TRead,AnyOut),'close_terminal':(TClose,AnyOut),'list_processes':(Empty,AnyOut),'get_process':(Pid,AnyOut),'kill_process':(Kill,AnyOut),'get_system_info':(Empty,AnyOut),'get_environment':(Empty,AnyOut),'set_environment':(EnvSet,AnyOut),'get_current_directory':(Empty,AnyOut),'create_python_venv':(Venv,AnyOut),'install_python_packages':(Pip,AnyOut),'run_python_script':(Py,AnyOut),'install_system_package':(Apt,AnyOut),'git_clone':(Clone,AnyOut),'git_status':(GitCwd,AnyOut),'git_diff':(Diff,AnyOut),'git_log':(Log,AnyOut),'git_branch':(Branch,AnyOut),'git_checkout':(Checkout,AnyOut),'git_commit':(Commit,AnyOut),'http_request':(Http,AnyOut),'download_url':(Download,AnyOut),'dns_lookup':(Dns,AnyOut),'check_port':(Port,AnyOut),'workspace_template':(Template,AnyOut)}
def t(n,d,c,i,o={'type':'object','additionalProperties':True}):return {'name':n,'description':d,'category':c,'inputSchema':i,'outputSchema':o}
OLD=(t('exec_command','Execute one shell command in the active task workspace.','shell',{'type':'object','additionalProperties':False,'properties':{'command':{'type':'string','minLength':1},'cwd':{'type':'string','default':'.'},'timeout_seconds':{'type':'integer','minimum':1,'maximum':1800,'default':120}},'required':['command']}),t('read_file','Read a UTF-8 workspace file.','filesystem',{'type':'object','additionalProperties':False,'properties':{'path':{'type':'string'},'start_line':{'type':'integer','default':1},'end_line':{'type':['integer','null'],'default':None},'max_bytes':{'type':'integer','default':262144}},'required':['path']}),t('write_file','Create or replace a UTF-8 workspace file.','filesystem',{'type':'object','additionalProperties':True,'properties':{'path':{'type':'string'},'content':{'type':'string'}},'required':['path','content']}),t('apply_patch','Apply exact text replacements after SHA verification.','filesystem',{'type':'object','additionalProperties':True,'properties':{'path':{'type':'string'},'expected_sha256':{'type':'string'},'replacements':{'type':'array'}},'required':['path','expected_sha256','replacements']}),t('list_directory','List workspace entries.','filesystem',{'type':'object','additionalProperties':True,'properties':{'path':{'type':'string','default':'.'}}}),t('search_files','Search workspace text files.','filesystem',{'type':'object','additionalProperties':True,'properties':{'query':{'type':'string'}},'required':['query']}))
CAT={'workspace_':'filesystem','terminal':'shell','process':'process','system':'system','environment':'system','current_directory':'system','python':'runtime','system_package':'runtime','git_':'git','http_':'network','download_url':'network','dns_':'network','check_port':'network','workspace_template':'templates'}
def cat(n):
 if n == 'workspace_template':return 'templates'
 if n in {'create_python_venv','install_python_packages','run_python_script','install_system_package'}:return 'runtime'
 for k,v in CAT.items():
  if k in n:return v
 return 'filesystem'
TOOLS=OLD+tuple(t(n,n.replace('_',' ').capitalize()+'.',cat(n),a.model_json_schema(),b.model_json_schema()) for n,(a,b) in MODELS.items())
def canonical_bytes(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def manifest(workspace_templates=None):return {'schema_version':2,'app_id':APP_ID,'version':VERSION,'tools':deepcopy(list(TOOLS)),'workspace_templates':deepcopy(workspace_templates or [])}
def manifest_sha256(v):return hashlib.sha256(canonical_bytes(v)).hexdigest()
