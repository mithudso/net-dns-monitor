#!/usr/bin/env bash
mkdir -p .github/ISSUE_TEMPLATE docs/archive scripts
touch .editorconfig .gitignore .gitattributes .env.example
touch .github/copilot-instructions.md CLAUDE.md AGENTS.md GEMINI.md memory.md prompts.md
touch docs/ARCHITECTURE.md docs/DEVELOPMENT.md docs/COMPONENTS.md docs/SECURITY.md docs/MCP.md docs/TESTING.md
touch docs/codebase-overview.md docs/high_signal_file_index.json docs/integrations-and-assumptions.md docs/known-issues.md docs/onboarding.md
touch docs/INSTALLATION.md docs/requirements.md docs/logging.md docs/caching-and-optimization.md docs/external-calls.md
echo "Bootstrap complete"
