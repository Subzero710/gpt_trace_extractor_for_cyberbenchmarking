import pytest
@pytest.mark.integration
@pytest.mark.asyncio
async def test_interaction(browser_v2):r,_=browser_v2;assert (await r.call('hover',{'selector':'#btn'}))['ok'];await r.call('select_option',{'selector':'#sel','values':['b']});assert await r.page.locator('#sel').input_value()=='b'
