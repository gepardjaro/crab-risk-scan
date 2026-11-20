"""Version 1 of the optional Pinch parser rules. Target code is only parsed."""
import ctypes
from functools import lru_cache
from html.parser import HTMLParser

from .rules import Hit


class Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hits = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if tag == "form" and key == "action" and value and value.strip().lower().startswith("http://"):
                self.hits.append(Hit("CRAB-HTML-001", self.getpos()[0], "medium",
                                     "Use HTTPS for this form destination."))


def html(source):
    parser = Forms()
    parser.feed(source)
    parser.close()
    return parser.hits


def postgres(source):
    from sqlfluff.core import FluffConfig, Lexer, Parser

    # Call the lexer and parser directly. No project config, templating or inline overrides.
    config = FluffConfig(overrides={"dialect": "postgres", "templater": "raw"},
                         ignore_local_config=True)
    tokens, errors = Lexer(config=config).lex(source)
    if errors:
        raise ValueError("SQL lexer error")
    tree = Parser(config=config).parse(tokens)
    if tree is None:
        return
    if any(tree.recursive_crawl("unparsable")):
        raise ValueError("SQL parser error")
    for statement in tree.recursive_crawl("access_statement"):
        words = [token.raw.upper() for token in statement.raw_segments if token.is_code]
        if not words or words[0] != "GRANT" or "ON" not in words or "TO" not in words:
            continue
        on, to = words.index("ON"), words.index("TO")
        # Explicit TABLE syntax distinguishes relation grants from grants on schemas/functions.
        if words[on + 1:on + 2] != ["TABLE"]:
            continue
        roles = words[to + 1:]
        for stop in ("WITH", "GRANTED"):
            if stop in roles:
                roles = roles[:roles.index(stop)]
        if "PUBLIC" in roles:
            yield Hit("CRAB-SQL-001", statement.pos_marker.source_position()[0], "medium",
                      "Review the privileges granted to PUBLIC on this table.")


@lru_cache(maxsize=2)
def mojo_parser(grammar):
    from tree_sitter import Language, Parser

    library = ctypes.CDLL(str(grammar))
    language = library.tree_sitter_mojo
    language.restype = ctypes.c_void_p
    # PyCapsule is the native grammar interface supported by py-tree-sitter.
    capsule = ctypes.pythonapi.PyCapsule_New
    capsule.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
    capsule.restype = ctypes.py_object
    return library, Parser(Language(capsule(language(), b"tree_sitter.Language", None)))


def mojo(source, grammar):
    if grammar is None:
        raise ImportError("Mojo grammar required")
    _, parser = mojo_parser(grammar)
    root = parser.parse(source.encode("utf-8")).root_node
    if root.has_error:
        raise ValueError("Mojo syntax unsupported")
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == "call":
            fn = node.child_by_field_name("function")
            if fn and fn.type == "subscript":
                fn = fn.child_by_field_name("value")
            if fn and fn.type == "identifier" and fn.text == b"external_call":
                yield Hit("CRAB-MOJO-001", node.start_point.row + 1, "info",
                          "Review types and lifetimes at this explicit foreign-call boundary.")
        if node.type not in {"string", "comment"}:
            pending.extend(reversed(node.named_children))
