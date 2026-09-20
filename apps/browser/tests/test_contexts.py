import pytest
@pytest.mark.integration
@pytest.mark.asyncio
async def test_contexts(browser_v2):r,u=browser_v2;await r.page.evaluate("localStorage.setItem('x','default')");c=await r.call('create_context',{});await r.call('navigate',{'url':u});assert await r.page.evaluate("localStorage.getItem('x')") is None;await r.call('destroy_context',{'context_id':c['context_id']})
