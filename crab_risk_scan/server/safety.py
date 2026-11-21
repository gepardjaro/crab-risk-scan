"""Lexical path checks and address classification shared by the server and the worker. Standard library only."""
import os


def unc_or_device(path):
    """UNC (`\\\\host\\share`, `//host/share`), device (`\\\\?\\`, `\\\\.\\`) and UNC-drive paths.
    Decided lexically, because resolving such a path would already open a network connection."""
    return len(path) >= 2 and path[0] in "\\/" and path[1] in "\\/"


def within(path, root):
    """Lexical containment after normalization; never touches the file system."""
    child, parent = os.path.normcase(os.path.normpath(path)), os.path.normcase(os.path.normpath(root))
    return child == parent or child.startswith(parent.rstrip("\\/") + os.sep)


def blocked_address(address):
    """Loopback, link-local, unspecified, multicast and reserved addresses, including IPv4-mapped IPv6."""
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return (address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast
            or address.is_reserved)


def host_allowed(host, port, default_port, allowed):
    """Exact, case-insensitive match against (host, port-or-None) entries. An entry without a port
    matches only the scheme's default port."""
    host = host.lower().rstrip(".")
    effective = port or default_port
    return any(name == host and (entry_port or default_port) == effective for name, entry_port in allowed)
