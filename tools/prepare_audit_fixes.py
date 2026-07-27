from pathlib import Path

path = Path(__file__).with_name("apply_audit_fixes.py")
text = path.read_text(encoding="utf-8")

replacements = (
    (
        "'''          g_sethardwarebreakpoint != NULL && g_deletehardwarebreakpoint != NULL &&'''",
        "'''         g_sethardwarebreakpoint != NULL && g_deletehardwarebreakpoint != NULL &&'''",
    ),
    (
        "'''          g_sethardwarebreakpoint != NULL && g_deletehardwarebreakbyaddr != NULL &&'''",
        "'''         g_sethardwarebreakpoint != NULL && g_deletehardwarebreakbyaddr != NULL &&'''",
    ),
    (
        r'''    ''' + "'''" + r'''\"hardware_breakpoint_validation\":true,\"execution_result_validation\":true,\"remote_clients\":false''',
        r'''    r''' + "'''" + r'''\"hardware_breakpoint_validation\":true,\"execution_result_validation\":true,\"remote_clients\":false''',
    ),
    (
        r'''    ''' + "'''" + r'''\"hardware_breakpoint_validation\":true,\"execution_result_validation\":true,\"hardware_breakpoint_address_delete\":true,\"debuggee_reset\":true,\"remote_clients\":false''',
        r'''    r''' + "'''" + r'''\"hardware_breakpoint_validation\":true,\"execution_result_validation\":true,\"hardware_breakpoint_address_delete\":true,\"debuggee_reset\":true,\"remote_clients\":false''',
    ),
    (
        '''            reached_probe = (
                isinstance(run_to_probe, dict)
                and run_to_probe.get("ok") is True
                and normalize_address(run_to_probe.get("eip", {}).get("eip"))
                == manifest.probe_address
            )
            if reached_probe:''',
        '''            reached_probe = False
            if isinstance(run_to_probe, dict) and run_to_probe.get("ok") is True:
                try:
                    reached_probe = (
                        normalize_address(run_to_probe.get("eip", {}).get("eip"))
                        == manifest.probe_address
                    )
                except (TypeError, ValueError):
                    reached_probe = False
            if reached_probe:''',
    ),
)

for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"prepare transformer: expected one match, found {count}: {old[:60]!r}")
    text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
