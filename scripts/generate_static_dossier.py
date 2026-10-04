#!/usr/bin/env python3
"""Generate a partial static repo dossier without indexing or executing source.

This is a census and retrieval map, not the full crawl-repo-to-llms workflow.
Every card is shallow. The recorded review scope describes the separate Group 4
audit and must not be mistaken for a deep-card or executable-inventory claim.
"""

import json
import subprocess
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs/llms"
REVIEWED = [
    "ai_consent",
    "alert",
    "cli",
    "cli_console",
    "commands",
    "console_window",
    "credentials_prompt",
    "dashboard",
    "distribution",
    "dock_icon",
    "domain_learner",
    "escalation",
    "flap_gate",
    "forensic_log",
    "graphs",
    "history",
    "log_watcher",
    "mini_window",
    "net_stats",
    "notifications",
    "peers",
    "ping_monitor",
    "query_log",
    "report",
    "report_storage",
    "resolution_log",
    "resolution_prober",
    "router_window",
    "settings_window",
    "stall_log",
    "state_machine",
    "status",
    "system_log",
]
ADDITIONS = (
    "scripts/check_docs.py",
    "scripts/generate_static_dossier.py",
    "tests/test_check_docs.py",
    "docs/repo-bootstrap-audit-2026-10-04.md",
    "docs/macos-networking-audit.md",
)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def role(path: str) -> str:
    if path.startswith("tests/"):
        return "test"
    if path.startswith(".github/"):
        return "infra"
    if path.startswith("scripts/"):
        return "tooling"
    if path.endswith((".md", ".txt")) and not path.startswith("requirements"):
        return "docs"
    if path.endswith((".yaml", ".toml", ".ini", ".plist", ".conf")):
        return "config"
    return "source"


def main() -> None:
    if OUT.exists() and (OUT / "manifest.json").exists():
        previous = json.loads((OUT / "manifest.json").read_text())
        if previous.get("generator") != "scripts/generate_static_dossier.py":
            raise SystemExit("Refusing to overwrite a dossier from another generator")
    elif OUT.exists():
        raise SystemExit("Refusing to overwrite an existing directory without a manifest")
    paths = set(git("ls-files").splitlines())
    paths.update(path for path in ADDITIONS if (ROOT / path).is_file())
    paths = sorted(path for path in paths if not path.startswith("docs/llms/"))
    index = json.loads((ROOT / "docs/high_signal_file_index.json").read_text())
    importance = {entry["path"]: entry["importance"] for entry in index["files"]}
    cards = [
        {
            "path": path,
            "role": role(path),
            "importance": importance.get(path, "ordinary"),
            "read_depth": "shallow",
            "purpose": f"Filename-based {role(path)} retrieval entry. [asserted]",
            "provenance": (f"[src: {path}#L1]" if (ROOT / path).stat().st_size else "[src: git]"),
        }
        for path in paths
    ]
    commit = git("rev-parse", "--short", "HEAD")
    remote_names = git("remote").splitlines()
    remote = "remote URL omitted" if remote_names else "no-remote"
    dirty = " dirty" if git("status", "--porcelain") else ""
    generated = date.today().isoformat()

    def header(purpose: str) -> str:
        return (
            f"# net-dns-monitor — {purpose}\n"
            f"> Source: {ROOT} · {remote} @ {commit}{dirty}\n"
            f"> Generated: {generated} by crawl-repo-to-llms v1.2.0 (partial static adapter)\n"
            f"> Census: {len(paths)} enumerated / 0 deep-read / {len(paths)} shallow"
            " · partial: census only; no deep cards or executable inventory\n\n"
        )

    routes = (
        "- Product/setup: README.md. [src: README.md#L1]\n"
        "- Agent constraints and verification: CLAUDE.md. [src: CLAUDE.md#L1]\n"
        "- Runtime architecture: docs/ARCHITECTURE.md. [src: docs/ARCHITECTURE.md#L1]\n"
        "- Component APIs: docs/COMPONENTS.md. [src: docs/COMPONENTS.md#L1]\n"
        "- External effects: docs/external-calls.md; its numeric anchors are dated. "
        "[src: docs/external-calls.md#L1]\n"
        "- Development-only semantic tools: docs/MCP.md. [src: docs/MCP.md#L1]\n"
        "- Test strategy: docs/TESTING.md. [src: docs/TESTING.md#L1]\n"
        "- Known limitations: docs/known-issues.md. [src: docs/known-issues.md#L1]\n"
        "- Release evidence: docs/APP_STORE_CHECKLIST.md and docs/APP_STORE_REVIEW_RESPONSE.md. "
        "[src: docs/APP_STORE_CHECKLIST.md#L1] [src: docs/APP_STORE_REVIEW_RESPONSE.md#L1]\n"
    )
    texts = {
        "llms.txt": header("retrieval entrypoint")
        + routes
        + "\nUse llms-filemap.txt for every census path. [asserted]\n",
        "llms-small.txt": header("small retrieval guide")
        + routes
        + "\nEvery filemap card is shallow. Deep review coverage is recorded separately "
        "in manifest.json; it does not imply full deep cards. [asserted]\n",
        "llms-facts.txt": header("bounded static facts")
        + "CI runs Ruff and the offline pytest suite, then the static documentation check. "
        "[src: .github/workflows/ci.yml#jobs]\n"
        + "The shipped defaults are checked against DEFAULT_CONFIG. "
        "[src: tests/test_config.py, asserted-by-test]\n"
        + "App Store release history is dated evidence, not current approval or certificate state. "
        "[src: docs/APP_STORE_CHECKLIST.md#L1]\n"
        + "The optional semantic index uses local Chroma and an Ollama embedding endpoint. "
        "[src: scripts/semantic_indexer.py#L1]\n",
        "llms-filemap.txt": header("complete source census with shallow cards")
        + "\n".join(
            f"- {card['path']} | {card['role']} | {card['importance']} | shallow. "
            f"{card['provenance']} Role and importance are retrieval hints. [asserted]"
            for card in cards
        )
        + "\n",
        "llms-infra.txt": header("infrastructure retrieval map")
        + "\n".join(
            f"- {card['path']}. {card['provenance']}"
            for card in cards
            if card["role"] in {"infra", "config", "tooling"}
        )
        + "\n",
        "llms-history.txt": header("dated history retrieval map")
        + "Prompts and work records are versioned in the repository journals. "
        "[src: prompts.md#L1] [src: memory.md#L1]\n"
        + "Release and review history must be read by date. "
        "[src: docs/APP_STORE_CHECKLIST.md#L1] [src: docs/APP_STORE_REVIEW_RESPONSE.md#L1]\n",
        "llms-indexes.txt": header("static and optional semantic retrieval maps")
        + "Static high-signal paths live in docs/high_signal_file_index.json. "
        "[src: docs/high_signal_file_index.json#L1]\n"
        + "Semantic tooling is developer-only and invokes an embedding service. "
        "[src: docs/MCP.md#L1]\n",
    }
    texts["llms-full.txt"] = header("bounded guide, not concatenated source") + routes
    assert len(texts["llms.txt"].encode()) <= 2000
    assert len(texts["llms-small.txt"].encode()) <= 8000
    emitted = sorted([*texts, "filemap.json", "manifest.json"])
    manifest = {
        "generator": "scripts/generate_static_dossier.py",
        "skill": "crawl-repo-to-llms",
        "skill_version": "1.2.0",
        "source": str(ROOT),
        "remote": remote,
        "commit": commit,
        "dirty": bool(dirty),
        "generated_at": generated,
        "enumerated": len(paths),
        "deep_read": 0,
        "shallow": len(paths),
        "partial": True,
        "partial_reason": "Static source census only; no deep cards or executable inventory.",
        "roles": dict(sorted(Counter(card["role"] for card in cards).items())),
        "tiers": dict(sorted(Counter(card["importance"] for card in cards).items())),
        "source_files": paths,
        "emitted_files": emitted,
        "deep_reviewed_paths": [f"netdnsmonitor/{name}.py" for name in REVIEWED],
        "deep_review_scope": "Group 4 maintainability audit; separate from dossier card depth.",
        "deferred_paths": paths,
        "redactions": [],
        "budget_used": "Static local census; no semantic service or source execution.",
    }
    OUT.mkdir(parents=True, exist_ok=True)
    for name, content in texts.items():
        (OUT / name).write_text(content, encoding="utf-8")
    (OUT / "filemap.json").write_text(json.dumps(cards, indent=2) + "\n")
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for name in ("llms.txt", "llms-small.txt", "llms-facts.txt", "llms-full.txt"):
        (ROOT / name).write_text(texts[name], encoding="utf-8")
    print(f"Generated {len(paths)} shallow source cards and {len(emitted)} dossier files.")


if __name__ == "__main__":
    main()
