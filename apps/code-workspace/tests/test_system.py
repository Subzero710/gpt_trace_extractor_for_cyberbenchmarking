from code_workspace.system import SystemService
def test_system(tmp_path):
 e={};s=SystemService(tmp_path,e,lambda:None);assert s.info({})['cpu']['count']>=1;s.set_env({'values':{'X':'1'}});assert e['X']=='1'
