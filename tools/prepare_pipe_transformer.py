from pathlib import Path

path = Path(__file__).with_name("apply_pipe_framing.py")
text = path.read_text(encoding="utf-8")
old = '''    '    assert "#define BRIDGE_PLUGIN_VERSION \\"2.7\\"" in SOURCE',
    '    assert "#define BRIDGE_PLUGIN_VERSION \\"2.8\\"" in SOURCE','''
new = '''    ''' + "'''" + '''    assert '#define BRIDGE_PLUGIN_VERSION "2.7"' in SOURCE''' + "'''" + ''',
    ''' + "'''" + '''    assert '#define BRIDGE_PLUGIN_VERSION "2.8"' in SOURCE''' + "'''" + ''','''
if text.count(old) != 1:
    raise RuntimeError(f"transformer quote literal: expected one match, found {text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
