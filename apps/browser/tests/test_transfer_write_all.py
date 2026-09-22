from browser_mcp.transfer import _write_all


def test_write_all_handles_short_writes():
    written = bytearray()
    def writer(_fd, data):
        count = min(2, len(data))
        written.extend(bytes(data[:count]))
        return count
    _write_all(123, b"abcdef", writer)
    assert bytes(written) == b"abcdef"
