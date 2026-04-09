import pytest
from pathlib import Path

# Skip this test cleanly if Playwright isn't installed in some environments.
pytest.importorskip("playwright")

from tools.web.browser_snapshot_tool import BrowserSnapshotTool


def test_browser_snapshot_example_com_smoke(tmp_path: Path) -> None:
    tool = BrowserSnapshotTool(results_dir=str(tmp_path))

    res = tool.snapshot("https://example.com", timeout_s=30)

    # Basic metadata
    assert res.final_url.startswith("https://example.com")
    assert "Example Domain" in res.title

    # Artifacts should exist
    assert Path(res.screenshot_path).exists()
    assert Path(res.html_path).exists()
    assert Path(res.json_path).exists()

    # Extracted signals should be the right types
    assert isinstance(res.links, list)
    assert isinstance(res.forms, list)
    assert isinstance(res.text_preview, str)

    # And should have some content for this page
    assert len(res.text_preview) > 0

def test_browser_snapshot_with_cookies(tmp_path: Path, mocker):
    # Mock playwright to avoid actual network call for this unit test
    mock_sync_playwright = mocker.patch("tools.web.browser_snapshot_tool.sync_playwright")
    mock_p = mock_sync_playwright.return_value.__enter__.return_value
    mock_browser = mock_p.chromium.launch.return_value
    mock_context = mock_browser.new_context.return_value
    mock_page = mock_context.new_page.return_value
    
    # Configure mocks to avoid TypeErrors during processing and JSON serialization
    mock_page.content.return_value = "<html><body>Mocked</body></html>"
    mock_page.title.return_value = "Mocked Page"
    mock_page.url = "https://example.com"
    mock_page.eval_on_selector.return_value = "Mocked body text"
    mock_page.eval_on_selector_all.return_value = []
    mock_context.cookies.return_value = []
    
    tool = BrowserSnapshotTool(results_dir=str(tmp_path))
    test_cookies = [{"name": "session", "value": "secret", "domain": "example.com", "path": "/"}]

    tool.snapshot("https://example.com", cookies=test_cookies)

    # Verify cookies were added to the context
    mock_context.add_cookies.assert_called_once_with(test_cookies)