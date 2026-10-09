RELEVANCE_SYSTEM = """You are a security expert. Given a CVE description and a Python function,
decide on a scale 0-10 how likely this function is the one that contains the vulnerability.
Respond with ONLY a single integer 0-10. No explanation."""


def relevance_user_prompt(cve_description: str, func: dict) -> str:
    body = func["body"]
    if len(body) > 4000:
        body = body[:4000] + "\n# ... [truncated]"
    return f"""CVE description:
{cve_description}

Function: {func['qualname']}  (file: {func['file']}, line {func['start_line']})
```python
{body}
```

Likelihood (0-10):"""


BATCH_SYSTEM = """You are a security expert ranking Python functions for vulnerability relevance.
For each function, output ONE line: <function_index>,<score_0_to_10>
Do not output anything else. Function index is the number shown in the prompt."""


def batch_user_prompt(cve_description: str, funcs: list[dict]) -> str:
    blocks = []
    for i, f in enumerate(funcs):
        body = f["body"]
        if len(body) > 1500:
            body = body[:1500] + "\n# ... [truncated]"
        blocks.append(
            f"--- Function {i}: {f['qualname']} ({f['file']}:{f['start_line']}) ---\n"
            f"```python\n{body}\n```"
        )
    return (
        f"CVE description:\n{cve_description}\n\n"
        + "\n\n".join(blocks)
        + "\n\nOutput one line per function: index,score"
    )
