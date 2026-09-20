import pytest
@pytest.mark.integration
@pytest.mark.asyncio
async def test_navigation(browser_v2):
 r,u=browser_v2;p=(await r.call('new_page',{'url':u}))['page_id'];assert (await r.call('switch_page',{'page_id':p}))['page_id']==p;assert (await r.call('reload',{}))['url']==u
