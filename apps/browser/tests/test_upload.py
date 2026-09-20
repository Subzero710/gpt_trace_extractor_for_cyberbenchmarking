import base64,pytest
@pytest.mark.integration
@pytest.mark.asyncio
async def test_upload(browser_v2):r,_=browser_v2;await r.call('upload_file',{'selector':'#file','filename':'x','content_base64':base64.b64encode(b'x').decode()});assert await r.page.locator('#file').evaluate('e=>e.files.length')==1
