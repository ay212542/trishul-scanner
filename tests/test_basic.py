"""
TRISHUL Scanner — Basic Tests
"""
import asyncio
import sys
import os

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from trishul.core.models import Finding, ScanConfig, ScanResult, Severity
from trishul.core.response_analyzer import ResponseAnalyzer
from trishul.plugins.loader import PluginLoader


def test_finding_creation():
    f = Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        url="http://example.com",
        description="Test description",
    )
    assert f.title == "Test Finding"
    assert f.severity == Severity.HIGH
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    print("✔ Finding creation test passed")


def test_scan_result_sorting():
    result = ScanResult(target_url="http://example.com")
    result.add_finding(Finding("Low Finding", Severity.LOW, "http://x.com", "desc"))
    result.add_finding(Finding("Critical Finding", Severity.CRITICAL, "http://x.com", "desc"))
    result.add_finding(Finding("High Finding", Severity.HIGH, "http://x.com", "desc"))
    sorted_f = result.sorted_findings()
    assert sorted_f[0].severity == Severity.CRITICAL
    assert sorted_f[1].severity == Severity.HIGH
    assert sorted_f[2].severity == Severity.LOW
    print("✔ Findings sorting test passed")


def test_response_analyzer_soft404():
    analyzer = ResponseAnalyzer()
    baseline = b"<html><body>Page Not Found</body></html>"
    analyzer.set_baseline(baseline)

    # Same body should be soft-404
    assert analyzer.is_soft_404(200, baseline)

    # Obviously real content should not be soft-404
    real = b"<html><body><h1>Welcome to our shop</h1><p>Products available</p></body></html>" * 10
    assert not analyzer.is_soft_404(200, real)
    print("✔ Response analyzer soft-404 test passed")


def test_scan_config_defaults():
    config = ScanConfig(target_url="http://example.com")
    assert config.depth == 3
    assert config.rate_limit == 10
    assert "crawler" in config.enabled_modules
    print("✔ ScanConfig defaults test passed")


async def test_plugin_loader():
    plugin_dir = os.path.join(os.path.dirname(__file__), "..", "trishul", "plugins")
    loader = PluginLoader([os.path.abspath(plugin_dir)])
    plugins = loader.load()
    assert len(plugins) >= 3, f"Expected at least 3 plugins, got {len(plugins)}"
    names = [p.name for p in plugins]
    print(f"✔ Plugin loader test passed — loaded: {names}")


def run_tests():
    print("\n" + "=" * 50)
    print("  TRISHUL Scanner — Test Suite")
    print("=" * 50 + "\n")

    test_finding_creation()
    test_scan_result_sorting()
    test_response_analyzer_soft404()
    test_scan_config_defaults()
    asyncio.run(test_plugin_loader())

    print("\n" + "=" * 50)
    print("  All tests passed! ✅")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    run_tests()
