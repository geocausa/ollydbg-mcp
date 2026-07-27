from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = (ROOT / "plugin_stub" / "build_plugin.ps1").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github" / "workflows" / "python.yml").read_text(encoding="utf-8")
TEST_HEADER = (ROOT / "tests" / "ollydbg_sdk_stub" / "Plugin.h").read_text(
    encoding="utf-8"
)


def test_real_build_script_enforces_legacy_plugin_requirements() -> None:
    for required_flag in (
        '"/TC"',
        '"/J"',
        '"/W4"',
        '"/WX"',
        '"/MACHINE:X86"',
        '"/DLL"',
    ):
        assert required_flag in BUILD_SCRIPT
    assert '"Kernel32.lib"' in BUILD_SCRIPT
    assert '"User32.lib"' in BUILD_SCRIPT
    assert '"Advapi32.lib"' in BUILD_SCRIPT
    assert "14C machine \\(x86\\)" in BUILD_SCRIPT


def test_build_script_verifies_every_required_ollydbg_export() -> None:
    for export_name in (
        "_ODBG_Plugindata",
        "_ODBG_Plugininit",
        "_ODBG_Pluginmenu",
        "_ODBG_Pluginaction",
        "_ODBG_Pluginclose",
        "_ODBG_Paused",
        "_ODBG_Pausedex",
        "_ODBG_Plugindestroy",
    ):
        assert export_name in BUILD_SCRIPT


def test_test_sdk_cannot_be_used_accidentally_for_a_real_build() -> None:
    assert "OLLYDBG_TEST_PLUGIN_H" in TEST_HEADER
    assert "Test-only compile shim for CI" in TEST_HEADER
    assert "$AllowTestSdk" in BUILD_SCRIPT
    assert "test-only SDK shim cannot be used for a real plugin build" in BUILD_SCRIPT
    assert "must not be distributed or loaded into OllyDbg" in BUILD_SCRIPT


def test_ci_builds_x86_dll_but_never_uploads_it() -> None:
    assert "native-dll:" in WORKFLOW
    assert "vcvarsall.bat\" x86" in WORKFLOW
    assert "-AllowTestSdk" in WORKFLOW
    assert "Remove the test-only DLL" in WORKFLOW
    assert "upload-artifact" not in WORKFLOW
