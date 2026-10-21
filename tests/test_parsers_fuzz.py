"""Property-based fuzz tests verifying parsers never raise exceptions on malformed input."""

from hypothesis import given, settings
from hypothesis import strategies as st

from sloth_soc.parsers.base import ParserContext
from sloth_soc.parsers.fail2ban import Fail2banParser
from sloth_soc.parsers.nginx import NginxParser
from sloth_soc.parsers.sshd import SSHDParser
from sloth_soc.parsers.ufw import UFWParser
from sloth_soc.schema import Event, Unparsed

CTX = ParserContext(file_path="fuzz.log", year_hint=2026)


@given(st.text(max_size=500))
@settings(max_examples=50)
def test_sshd_parser_fuzz_text(line: str):
    parser = SSHDParser()
    res = parser.parse_line(line, line_no=1, ctx=CTX)
    assert isinstance(res, (Event, Unparsed))


@given(st.text(max_size=500))
@settings(max_examples=50)
def test_nginx_parser_fuzz_text(line: str):
    parser = NginxParser()
    res = parser.parse_line(line, line_no=1, ctx=CTX)
    assert isinstance(res, (Event, Unparsed))


@given(st.text(max_size=500))
@settings(max_examples=50)
def test_fail2ban_parser_fuzz_text(line: str):
    parser = Fail2banParser()
    res = parser.parse_line(line, line_no=1, ctx=CTX)
    assert isinstance(res, (Event, Unparsed))


@given(st.text(max_size=500))
@settings(max_examples=50)
def test_ufw_parser_fuzz_text(line: str):
    parser = UFWParser()
    res = parser.parse_line(line, line_no=1, ctx=CTX)
    assert isinstance(res, (Event, Unparsed))
