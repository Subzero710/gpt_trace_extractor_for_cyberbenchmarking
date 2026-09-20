import pytest
@pytest.mark.integration
@pytest.mark.asyncio
async def test_logs(browser_v2):r,_=browser_v2;await r.page.locator('#btn').click();assert any(x['text']=='clicked' for x in (await r.call('get_console_logs',{}))['entries'])
