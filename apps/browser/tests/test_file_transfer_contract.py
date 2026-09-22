import pytest
from pydantic import ValidationError
from browser_mcp.contracts import Upload

def test_upload_requires_exactly_one_source():
 Upload(selector="#f",file_id="f_"+"a"*64)
 Upload(selector="#f",filename="x",content_base64="eA==")
 with pytest.raises(ValidationError):Upload(selector="#f")
 with pytest.raises(ValidationError):Upload(selector="#f",file_id="f_"+"a"*64,filename="x",content_base64="eA==")
