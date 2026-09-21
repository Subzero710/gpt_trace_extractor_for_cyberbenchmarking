from __future__ import annotations
import json
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
class OpOut(M):
 ok:bool
 path:str|None=None
 source:str|None=None
 destination:str|None=None
class StatOut(M):
 path:str;type:Literal['file','directory','other'];size:int|None;mode:str;mtime:float;sha256:str|None
class EntriesOut(M):
 path:str;entries:list[dict[str,Any]];truncated:bool
class TerminalOut(M):
 terminal_id:str;pid:int;cwd:str;status:str;stdout:str|None=None;stderr:str|None=None;stdout_truncated:bool|None=None;stderr_truncated:bool|None=None;exit_code:int|None=None
class ProcessOut(M):
 pid:int;command:str;status:str;start_time:float;runtime:float
class ProcessesOut(M):processes:list[ProcessOut]
class EnvironmentOut(M):environment:dict[str,str]
class CwdOut(M):cwd:str;absolute_path:str
class SystemInfoOut(M):
 os:dict[str,str];architecture:str;cpu:dict[str,Any];ram:dict[str,int];disk:dict[str,int];cwd:str
class CommandOut(M):
 command:list[str];cwd:str;stdout:str;stderr:str;exit_code:int;timed_out:bool;stdout_truncated:bool;stderr_truncated:bool
class HttpOut(M):
 url:str;status:int;headers:dict[str,str];body:str;size:int;truncated:bool
class DownloadOut(M):url:str;path:str;size:int;sha256:str
class DnsOut(M):hostname:str;addresses:list[str]
class PortOut(M):host:str;port:int;open:bool;latency_ms:float|None
class TemplateOut(M):template_id:str;template_version:str;template_hash:str;active:bool|None=None
MODELS={'workspace_delete_file':(PathIn,OpOut),'workspace_delete_directory':(DelDir,OpOut),'workspace_move':(Move,OpOut),'workspace_copy':(Move,OpOut),'workspace_create_directory':(Mk,OpOut),'workspace_stat':(PathIn,StatOut),'workspace_tree':(Tree,EntriesOut),'workspace_find':(Find,EntriesOut),'create_terminal':(TCreate,TerminalOut),'send_terminal_input':(TSend,TerminalOut),'read_terminal_output':(TRead,TerminalOut),'close_terminal':(TClose,TerminalOut),'list_processes':(Empty,ProcessesOut),'get_process':(Pid,ProcessOut),'kill_process':(Kill,ProcessOut),'get_system_info':(Empty,SystemInfoOut),'get_environment':(Empty,EnvironmentOut),'set_environment':(EnvSet,EnvironmentOut),'get_current_directory':(Empty,CwdOut),'create_python_venv':(Venv,CommandOut),'install_python_packages':(Pip,CommandOut),'run_python_script':(Py,CommandOut),'install_system_package':(Apt,CommandOut),'git_clone':(Clone,CommandOut),'git_status':(GitCwd,CommandOut),'git_diff':(Diff,CommandOut),'git_log':(Log,CommandOut),'git_branch':(Branch,CommandOut),'git_checkout':(Checkout,CommandOut),'git_commit':(Commit,CommandOut),'http_request':(Http,HttpOut),'download_url':(Download,DownloadOut),'dns_lookup':(Dns,DnsOut),'check_port':(Port,PortOut),'workspace_template':(Template,TemplateOut)}
def t(n,d,c,i,o):return {'name':n,'description':d,'category':c,'inputSchema':i,'outputSchema':o}
OLD=({'description': 'Execute one shell command in the active task workspace and return bounded stdout, stderr, exit status, and timeout state.', 'inputSchema': {'additionalProperties': False, 'properties': {'command': {'description': 'Shell command to execute with /bin/bash.', 'minLength': 1, 'type': 'string'}, 'cwd': {'default': '.', 'description': 'Working directory relative to the task workspace.', 'type': 'string'}, 'timeout_seconds': {'default': 120, 'description': 'Wall-clock timeout in seconds.', 'maximum': 1800, 'minimum': 1, 'type': 'integer'}}, 'required': ['command'], 'type': 'object'}, 'name': 'exec_command', 'category': 'shell', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Read a UTF-8 text file inside the active task workspace without following paths outside it.', 'inputSchema': {'additionalProperties': False, 'properties': {'end_line': {'default': None, 'minimum': 1, 'type': ['integer', 'null']}, 'max_bytes': {'default': 262144, 'maximum': 1048576, 'minimum': 1, 'type': 'integer'}, 'path': {'description': 'File path relative to the task workspace.', 'minLength': 1, 'type': 'string'}, 'start_line': {'default': 1, 'minimum': 1, 'type': 'integer'}}, 'required': ['path'], 'type': 'object'}, 'name': 'read_file', 'category': 'filesystem', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Create or replace one UTF-8 text file inside the active task workspace.', 'inputSchema': {'additionalProperties': False, 'properties': {'content': {'description': 'Complete UTF-8 file content.', 'type': 'string'}, 'create_parents': {'default': True, 'type': 'boolean'}, 'expected_sha256': {'default': None, 'description': 'When set, the existing file must have this SHA-256 before replacement.', 'pattern': '^[0-9a-f]{64}$', 'type': ['string', 'null']}, 'overwrite': {'default': True, 'type': 'boolean'}, 'path': {'description': 'File path relative to the task workspace.', 'minLength': 1, 'type': 'string'}}, 'required': ['path', 'content'], 'type': 'object'}, 'name': 'write_file', 'category': 'filesystem', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Apply ordered, exact text replacements to one workspace file after verifying its SHA-256.', 'inputSchema': {'additionalProperties': False, 'properties': {'expected_sha256': {'pattern': '^[0-9a-f]{64}$', 'type': 'string'}, 'path': {'minLength': 1, 'type': 'string'}, 'replacements': {'items': {'additionalProperties': False, 'properties': {'expected_count': {'default': 1, 'minimum': 1, 'type': 'integer'}, 'new': {'type': 'string'}, 'old': {'minLength': 1, 'type': 'string'}}, 'required': ['old', 'new'], 'type': 'object'}, 'minItems': 1, 'type': 'array'}}, 'required': ['path', 'expected_sha256', 'replacements'], 'type': 'object'}, 'name': 'apply_patch', 'category': 'filesystem', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'List workspace entries in deterministic path order without following symlinks.', 'inputSchema': {'additionalProperties': False, 'properties': {'max_entries': {'default': 1000, 'maximum': 10000, 'minimum': 1, 'type': 'integer'}, 'path': {'default': '.', 'type': 'string'}, 'recursive': {'default': False, 'type': 'boolean'}}, 'type': 'object'}, 'name': 'list_directory', 'category': 'filesystem', 'outputSchema': {'type': 'object', 'additionalProperties': True}}, {'description': 'Search UTF-8 workspace files for a literal string and return deterministic structured matches.', 'inputSchema': {'additionalProperties': False, 'properties': {'case_sensitive': {'default': False, 'type': 'boolean'}, 'file_glob': {'default': '**/*', 'type': 'string'}, 'max_results': {'default': 100, 'maximum': 1000, 'minimum': 1, 'type': 'integer'}, 'path': {'default': '.', 'type': 'string'}, 'query': {'minLength': 1, 'type': 'string'}}, 'required': ['query'], 'type': 'object'}, 'name': 'search_files', 'category': 'filesystem', 'outputSchema': {'type': 'object', 'additionalProperties': True}})
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
