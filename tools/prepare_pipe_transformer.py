from pathlib import Path

path = Path(__file__).with_name("apply_pipe_framing.py")
lines = path.read_text(encoding="utf-8").splitlines()
label = '    "native plugin version assertion",'
if lines.count(label) != 1:
    raise RuntimeError(
        f"transformer version label: expected one match, found {lines.count(label)}"
    )
label_index = lines.index(label)
old_index = label_index - 2
new_index = label_index - 1
if "BRIDGE_PLUGIN_VERSION" not in lines[old_index] or "2.7" not in lines[old_index]:
    raise RuntimeError("transformer old version literal was not found at expected location")
if "BRIDGE_PLUGIN_VERSION" not in lines[new_index] or "2.8" not in lines[new_index]:
    raise RuntimeError("transformer new version literal was not found at expected location")
lines[old_index] = "    '''    assert '#define BRIDGE_PLUGIN_VERSION \"2.7\"' in SOURCE''',"
lines[new_index] = "    '''    assert '#define BRIDGE_PLUGIN_VERSION \"2.8\"' in SOURCE''',"
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
