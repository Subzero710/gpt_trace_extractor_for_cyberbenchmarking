from gpt_trace_runner.superbench.models import *
def test_stable_identity():
    a=canonical_id('original-source','1','repo','origin'); b=canonical_id('original-source','1','repo','origin'); assert a==b
    c=TeacherCampaign('gpt',{'x':1},'abc'); assert c.campaign_id==TeacherCampaign('gpt',{'x':1},'abc').campaign_id
