"""Check the public source allowlist without recording private identifiers."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {
    ".github", "cmd", "internal", "registry", "packaging", "tests", "docs", "reference",
    ".gitignore", ".dockerignore", ".go-version", ".golangci.yml", "Makefile", "README.md",
    "LICENSE", "go.mod", "go.sum", "Containerfile",
}
BAD_NAMES = {"vault", "inventory", "inventories", "build-inputs", "__pycache__", "captures"}
PATTERNS = [
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(rb"/home/" + rb"[^/\s]+/"),
    re.compile(rb"[a-zA-Z0-9.-]+\.xyz\b"),
]


def check(paths):
    errors = []
    for relative in paths:
        path = ROOT / relative
        if path.parts[-1] == "registry" and path.is_symlink():
            if not path.resolve().is_relative_to(ROOT):
                errors.append(f"{relative}: symlink outside repository")
            continue
        if Path(relative).parts[0] not in ALLOWED or BAD_NAMES.intersection(Path(relative).parts):
            errors.append(f"{relative}: excluded source path")
            continue
        if path.suffix in {".pcap", ".pcapng", ".db", ".sqlite", ".log", ".stderr", ".pem", ".key"}:
            errors.append(f"{relative}: private or generated artifact")
            continue
        if relative.startswith("registry/") and path.name != "assets.go":
            continue  # Hash-pinned public upstream data and its license.
        data = path.read_bytes()
        for pattern in PATTERNS:
            if pattern.search(data):
                errors.append(f"{relative}: private file or identifier pattern")
                break
    return errors


if __name__ == "__main__":
    paths = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, text=True).splitlines()
    errors = check(paths)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        raise SystemExit(1)
    print(f"Public source check passed: {len(paths)} files.")
