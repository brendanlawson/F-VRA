from __future__ import annotations

_CWE_HINTS = {
    "CWE-20": "improper input validation untrusted input validation sanitization",
    "CWE-22": "path traversal directory traversal filesystem path normalization",
    "CWE-78": "operating system command injection shell execution untrusted command",
    "CWE-79": "cross-site scripting output encoding HTML escaping",
    "CWE-89": "SQL injection query parameterization untrusted database input",
    "CWE-94": "code injection dynamic evaluation execution",
    "CWE-200": "exposure of sensitive information data disclosure",
    "CWE-287": "improper authentication identity verification credentials",
    "CWE-352": "cross-site request forgery request origin token validation",
    "CWE-400": "resource exhaustion denial of service unbounded allocation loop",
    "CWE-502": "deserialization of untrusted data object reconstruction unsafe loader",
    "CWE-611": "XML external entity entity expansion XML parser",
    "CWE-918": "server-side request forgery URL request network destination validation",
}


def expand_description(
    description: str,
    cwe_id: str | None,
    *,
    original_repeat: int = 1,
) -> str:
    description = description.strip()
    hint = _CWE_HINTS.get((cwe_id or "").upper(), "")
    repeated = "\n".join([description] * max(1, original_repeat))
    return f"{repeated}\n{hint}".strip()
