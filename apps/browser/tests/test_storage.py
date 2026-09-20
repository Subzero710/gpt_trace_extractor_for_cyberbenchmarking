import pytest
@pytest.mark.integration
@pytest.mark.asyncio
async def test_storage(browser_v2):r,u=browser_v2;await r.call('set_cookie',{'name':'x','value':'1','url':u});s=await r.call('export_storage_state',{});await r.call('clear_cookies',{});await r.call('import_storage_state',{'content_base64':s['content_base64']});assert (await r.call('get_cookies',{}))['cookies']
