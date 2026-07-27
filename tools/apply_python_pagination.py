from pathlib import Path


PATH = Path("ollydbg_mcp/client.py")
source = PATH.read_text(encoding="utf-8")


def replace_once(old: str, new: str, name: str) -> None:
    global source
    matches = source.count(old)
    if matches != 1:
        raise RuntimeError(f"{name}: expected 1 match, found {matches}")
    source = source.replace(old, new, 1)


replace_once(
    '''from .transport import BridgeTransport, NamedPipeTransport


@dataclass(slots=True)
''',
    '''from .transport import BridgeTransport, NamedPipeTransport

TABLE_PAGE_SIZES = {
    "list_breakpoints": 32,
    "list_modules": 8,
    "list_threads": 32,
}
MAX_TABLE_PAGES = 4096
MAX_TABLE_ITEMS = 100_000


@dataclass(slots=True)
''',
    "pagination constants",
)

replace_once(
    '''    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        payload = {"protocol_version": 1, **payload}
        assert self.transport is not None
        return self._augment_status(self.transport.request(payload))

    def status(self) -> dict[str, Any]:
''',
    '''    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        payload = {"protocol_version": 1, **payload}
        assert self.transport is not None
        return self._augment_status(self.transport.request(payload))

    def _collect_table_pages(self, command: str, item_key: str) -> dict[str, Any]:
        page_size = TABLE_PAGE_SIZES[command]
        offset = 0
        pages = 0
        collected: list[Any] = []
        reported_count: int | None = None

        while pages < MAX_TABLE_PAGES:
            page = self._request(
                {
                    "command": command,
                    "offset": offset,
                    "limit": page_size,
                }
            )
            items = page.get(item_key)
            if not isinstance(items, list):
                raise BridgeError(f"{command}: response field {item_key!r} is not a list")
            collected.extend(items)
            pages += 1
            if len(collected) > MAX_TABLE_ITEMS:
                raise BridgeError(f"{command}: table exceeds the supported item limit")

            page_count = page.get("count")
            if isinstance(page_count, int) and page_count >= 0:
                reported_count = page_count

            if page.get("has_more") is not True:
                result = dict(page)
                result[item_key] = collected
                result["count"] = (
                    reported_count if reported_count is not None else len(collected)
                )
                result["offset"] = 0
                result["limit"] = page_size
                result["returned"] = len(collected)
                result["has_more"] = False
                result["next_offset"] = len(collected)
                result["pages"] = pages
                return result

            next_offset = page.get("next_offset")
            if not isinstance(next_offset, int) or next_offset <= offset:
                raise BridgeError(f"{command}: paginated response made no forward progress")
            if not items:
                raise BridgeError(f"{command}: paginated response returned an empty page")
            offset = next_offset

        raise BridgeError(f"{command}: pagination exceeded {MAX_TABLE_PAGES} pages")

    def status(self) -> dict[str, Any]:
''',
    "pagination collector",
)

replace_once(
    '''                "native_wait_for_pause": bool(
                    status.get("capabilities", {}).get("native_wait_for_pause")
                ),
                "atomic_snapshot": False,
''',
    '''                "native_wait_for_pause": bool(
                    status.get("capabilities", {}).get("native_wait_for_pause")
                ),
                "paged_tables": bool(
                    status.get("capabilities", {}).get("paged_tables")
                ),
                "atomic_snapshot": False,
''',
    "pagination capability",
)

replace_once(
    '''    def list_breakpoints(self) -> dict[str, Any]:
        return self._request({"command": "list_breakpoints"})

    def list_modules(self) -> dict[str, Any]:
        return self._request({"command": "list_modules"})

    def list_threads(self) -> dict[str, Any]:
        return self._request({"command": "list_threads"})
''',
    '''    def list_breakpoints(self) -> dict[str, Any]:
        return self._collect_table_pages("list_breakpoints", "breakpoints")

    def list_modules(self) -> dict[str, Any]:
        return self._collect_table_pages("list_modules", "modules")

    def list_threads(self) -> dict[str, Any]:
        return self._collect_table_pages("list_threads", "threads")
''',
    "public paginated list methods",
)

PATH.write_text(source, encoding="utf-8", newline="\n")
