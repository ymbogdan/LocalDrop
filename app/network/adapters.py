from __future__ import annotations

import ipaddress
import socket
import struct

_VIRTUAL_TYPES = {23, 24, 131}
_BLOCKED_NAMES = (
    "virtual",
    "vpn",
    "hyper-v",
    "vethernet",
    "wsl",
    "tailscale",
    "tunnel",
    "bluetooth",
    "loopback",
    "docker",
    "vmware",
    "virtualbox",
    "teredo",
    "isatap",
    "pseudo",
)


def adapter_allowed(if_type: int, name: str, status: int) -> bool:
    if status != 1:
        return False
    text = name.lower()
    if any(word in text for word in _BLOCKED_NAMES):
        return False
    if if_type in _VIRTUAL_TYPES:
        return False
    return True


def interface_allowed(index: int) -> bool | None:
    allowed = _allowed_indexes()
    if allowed is None:
        return None
    return index in allowed


def local_on_allowed_adapter(address: str) -> bool:
    host = address.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return True
    allowed = _allowed_indexes()
    if allowed is None:
        return True
    index = _index_for(str(ip))
    if index is None:
        return False
    return index in allowed


def _allowed_indexes() -> set[int] | None:
    found = _enumerate_adapters()
    if found is None:
        return None
    allowed = {index for index, if_type, name, status in found if adapter_allowed(if_type, name, status)}
    if not allowed and found:
        return set()
    if not found:
        return None
    return allowed


def _enumerate_adapters() -> list[tuple[int, int, str, int]] | None:
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None
    if not hasattr(ctypes, "windll"):
        return None

    class _Addresses(ctypes.Structure):
        pass

    _Addresses._fields_ = [
        ("Length", wintypes.ULONG),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(_Addresses)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.c_void_p),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
        ("Mtu", wintypes.DWORD),
        ("IfType", wintypes.DWORD),
        ("OperStatus", wintypes.DWORD),
    ]

    size = wintypes.ULONG(16_000)
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value)
        try:
            result = ctypes.windll.iphlpapi.GetAdaptersAddresses(
                0,
                0x10,
                None,
                ctypes.cast(buffer, ctypes.POINTER(_Addresses)),
                ctypes.byref(size),
            )
        except (AttributeError, OSError):
            return None
        if result == 0:
            break
        if result != 111:
            return None
    else:
        return None
    found: list[tuple[int, int, str, int]] = []
    current = ctypes.cast(buffer, ctypes.POINTER(_Addresses))
    while current:
        item = current.contents
        name = item.FriendlyName or item.Description or ""
        found.append((int(item.IfIndex), int(item.IfType), str(name), int(item.OperStatus)))
        if not item.Next:
            break
        current = item.Next
    return found


def _index_for(address: str) -> int | None:
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None
    if not hasattr(ctypes, "windll"):
        return None

    class _Row(ctypes.Structure):
        _fields_ = [
            ("dwAddr", wintypes.DWORD),
            ("dwIndex", wintypes.DWORD),
            ("dwMask", wintypes.DWORD),
            ("dwBCastAddr", wintypes.DWORD),
            ("dwReasmSize", wintypes.DWORD),
            ("unused1", wintypes.WORD),
            ("wType", wintypes.WORD),
        ]

    class _Table(ctypes.Structure):
        _fields_ = [("dwNumEntries", wintypes.DWORD), ("table", _Row * 64)]

    table = _Table()
    size = wintypes.DWORD(ctypes.sizeof(table))
    try:
        result = ctypes.windll.iphlpapi.GetIpAddrTable(ctypes.byref(table), ctypes.byref(size), 0)
    except (AttributeError, OSError):
        return None
    if result != 0:
        return None
    count = min(int(table.dwNumEntries), 64)
    for index in range(count):
        row = table.table[index]
        text = socket.inet_ntoa(struct.pack("<L", row.dwAddr))
        if text == address:
            return int(row.dwIndex)
    return None
