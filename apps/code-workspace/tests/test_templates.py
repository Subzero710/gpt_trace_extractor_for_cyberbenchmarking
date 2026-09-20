import os,json
from code_workspace.templates import TemplateManager
def test_templates(tmp_path):
 root=tmp_path/'t';(root/'empty').mkdir(parents=True);import code_workspace.templates as t;h=t.hash_template(root/'empty');(root/'manifest.json').write_text(json.dumps({'schema_version':1,'templates':[{'id':'empty','version':'1','description':'x','hash':h}]}));m=TemplateManager(root,tmp_path/'w',os.getuid(),os.getgid());assert m.apply({'template_id':'empty'})['template_hash']==h
