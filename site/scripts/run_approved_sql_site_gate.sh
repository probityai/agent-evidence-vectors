#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
toolchain="$PWD/.atlas-toolchain"
mkdir -p "$toolchain"
curl -fsSL https://github.com/astral-sh/uv/releases/download/0.12.24/uv-x86_64-unknown-linux-gnu.tar.gz -o "$toolchain/uv.tar.gz"
printf '%s  %s\n' b4dfaef47d491a7296981f8374a4595f55dbf84e8937c8ecd2983574d8bb3da6 "$toolchain/uv.tar.gz" | sha256sum -c -
tar -xzf "$toolchain/uv.tar.gz" -C "$toolchain"
export PATH="$toolchain/uv-x86_64-unknown-linux-gnu:$PATH"
export UV_CACHE_DIR="$toolchain/cache"
export UV_PYTHON_INSTALL_DIR="$toolchain/python"
uv --version
# Use fresh managed interpreters so a warm runner cannot hide obsolete metadata.
uv python install 3.12.14 3.14.7
uv venv --python 3.12.14 .venv
uv pip install --python .venv/bin/python -r requirements/public-layout.txt

# Match the site's existing pinned Pandoc job, without changing shared packages.
mkdir -p .venv/toolchain
curl -fsSL https://github.com/jgm/pandoc/releases/download/3.3/pandoc-3.3-1-amd64.deb -o .venv/pandoc.deb
printf '%s  %s\n' 7a6625d5aeb6b8666375807a3e16cc00659c48fb88299707651f60d88c31a360 .venv/pandoc.deb | sha256sum -c -
dpkg-deb -x .venv/pandoc.deb .venv/toolchain
export PATH="$PWD/.venv/toolchain/usr/bin:$PATH"
pandoc --version
.venv/bin/python scripts/qualify_approved_sql_site.py
