"""Fixed hostile-target corpus for policy/ (task-a-design.md section 6, STR-A2).

Data only. Only ``.test``, ``.example`` and RFC 5737 / RFC 3849 documentation
addresses plus loopback / link-local literals that the parser must classify;
no real third-party hostname appears anywhere. Rows are
``(raw, host, port, scheme)`` for ACCEPT and ``(raw, code)`` for REJECT.
"""

from __future__ import annotations

LABEL63 = "a" * 63
LABEL64 = "a" * 64
# 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253 characters; one more character gives 254.
HOST253 = ".".join([LABEL63, LABEL63, LABEL63, "d" * 61])
HOST254 = ".".join([LABEL63, LABEL63, LABEL63, "d" * 62])

# (raw, canonical host, port, scheme)
ACCEPT: tuple[tuple[str, str, int | None, str | None], ...] = (
    ("127.1", "127.0.0.1", None, None),
    ("2130706433", "127.0.0.1", None, None),
    ("0x7f000001", "127.0.0.1", None, None),
    ("0177.0.0.1", "127.0.0.1", None, None),
    ("0x7f.1", "127.0.0.1", None, None),
    ("127.0.0.1.", "127.0.0.1", None, None),
    ("[::ffff:7f00:1]", "127.0.0.1", None, None),
    ("::ffff:169.254.169.254", "169.254.169.254", None, None),
    ("[::FFFF:A9FE:A9FE]", "169.254.169.254", None, None),
    ("0:0:0:0:0:ffff:a9fe:a9fe", "169.254.169.254", None, None),
    ("64:ff9b::a9fe:a9fe", "64:ff9b::a9fe:a9fe", None, None),
    ("2002:a9fe:a9fe::1", "2002:a9fe:a9fe::1", None, None),
    ("①②⑦．⓪．⓪．①", "127.0.0.1", None, None),
    ("１２７。０。０。１", "127.0.0.1", None, None),
    ("HOST.", "host", None, None),
    ("Host:8080", "host", 8080, None),
    ("http://Host", "host", 80, "http"),
    ("HTTPS://Host", "host", 443, "https"),
    ("https://h.test:8443/p?q#f", "h.test", 8443, "https"),
    ("http://1.2.3.4/8", "1.2.3.4", 80, "http"),
    ("a#@b", "a", None, None),
    ("[::1]:80", "::1", 80, None),
    ("[2001:db8::1]", "2001:db8::1", None, None),
    ("2001:db8::1", "2001:db8::1", None, None),
    ("under_score.test", "under_score.test", None, None),
    (LABEL63 + ".test", LABEL63 + ".test", None, None),
    (HOST253, HOST253, None, None),
)

# (raw, stable code)
REJECT: tuple[tuple[str, str], ...] = (
    ("", "length"),
    ("a" * 2049, "length"),
    ("a@b", "userinfo"),
    ("a\\@b", "charset"),
    ("http://evil.test\\@allowed.test", "charset"),
    ("a%2540b", "charset"),
    ("a\tb", "charset"),
    ("a\nb", "charset"),
    ("a\x00b", "charset"),
    ("a b", "charset"),
    ("a​b", "charset"),
    ("a‮b", "charset"),
    ("a\ud800b", "charset"),
    ("::1%eth0", "charset"),
    ("a..b", "label"),
    (".", "host"),
    ("a.b..", "dots"),
    (LABEL64 + ".test", "label"),
    (HOST254, "hostlen"),
    ("xn--.test", "punycode"),
    ("host:0", "port"),
    ("host:65536", "port"),
    ("host:", "port"),
    ("host:+80", "port"),
    ("1_27.0.0.1", "ipv4"),
    ("0x1_0.0.0.1", "ipv4"),
    ("127.0.0.1:8_0", "port"),
    ("127.0.0.1:٨٠", "port"),
    ("host:²", "port"),
    ("0x7f.0x_0.0.1", "ipv4"),
    ("256.1.1.1", "ipv4"),
    ("1.2.3.4.5", "ipv4"),
    ("999999999999", "ipv4"),
    ("08.1.1.1", "ipv4"),
    ("abc.0x", "ipv4"),
    ("http://evil.test＠allowed.test", "charset"),
    ("evil.test／x", "charset"),
    ("evil.test：80@a", "userinfo"),
    ("℀.test", "charset"),
    ("straße.test", "idna"),
    ("ftp://h", "scheme"),
    ("file:///etc", "scheme"),
    ("gopher://h", "scheme"),
    ("//h", "scheme"),
    ("http:h", "port"),
    ("10.0.0.0/8", "cidr_target"),
    ("169.0.0.0/8", "cidr_target"),
    ("::/0", "cidr_target"),
    ("1.2.3.4/8", "cidr_target"),
    ("[::1", "ipv6"),
    ("[1.2.3.4]", "ipv6"),
    ("[::1]x", "ipv6"),
    ("::g", "ipv6"),
)

# Every encoding of the same address must give the same canonical IP.
LOOPBACK_ENCODINGS: tuple[str, ...] = (
    "127.0.0.1",
    "127.1",
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "0x7f.1",
    "127.0.0.1.",
    "[::ffff:7f00:1]",
    "::ffff:127.0.0.1",
    "１２７。０。０。１",
)
METADATA_ENCODINGS: tuple[str, ...] = (
    "169.254.169.254",
    "0xA9FEA9FE",
    "2852039166",
    "0251.0376.0251.0376",
    "169.254.43518",
    "[::ffff:a9fe:a9fe]",
    "::ffff:169.254.169.254",
    "[0:0:0:0:0:FFFF:169.254.169.254]",
)
