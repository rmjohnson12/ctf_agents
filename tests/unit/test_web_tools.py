import pytest
from tools.web.sqlmap import SqlmapTool
from tools.web.dirsearch import DirsearchTool
from tools.common.result import ToolResult

class MockRunner:
    def __init__(self, stdout):
        self.stdout = stdout
    def run(self, argv, timeout_s=None, cwd=None, env=None):
        return ToolResult(argv, self.stdout, "", 0, False, 0.1)

def test_sqlmap_vulnerable_parsing():
    stdout = "some noise... back-end DBMS: MySQL ... Payload: id=1 UNION SELECT ... is vulnerable"
    tool = SqlmapTool(runner=MockRunner(stdout))
    res = tool.run("http://test.local")
    assert res.vulnerable is True
    assert res.db_type == "MySQL"
    assert len(res.payloads) > 0

def test_dirsearch_parsing():
    stdout = """
[10:00:00] 200 -   1KB - /admin.php
[10:00:01] 404 -   0B  - /notfound
[10:00:02] 200 -   5KB - /config.txt
"""
    tool = DirsearchTool(runner=MockRunner(stdout))
    res = tool.run("http://test.local")
    assert len(res.entries) == 2
    assert res.entries[0].url == "/admin.php"
    assert res.entries[0].status == 200
    assert res.entries[1].url == "/config.txt"
