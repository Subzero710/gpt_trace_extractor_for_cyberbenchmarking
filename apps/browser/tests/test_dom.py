import pytest
@pytest.mark.integration
@pytest.mark.asyncio
async def test_dom(browser_v2):r,_=browser_v2;assert (await r.call('query_selector',{'selector':'#btn'}))['count']==1;assert (await r.call('evaluate_javascript',{'expression':'() => 42'}))['result']==42
