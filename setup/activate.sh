# Source from bash or zsh. ASAHI_ROOT may select an existing external workspace.
if [ -n "${ZSH_VERSION:-}" ]; then
    _research_source="${(%):-%N}"
else
    _research_source="${BASH_SOURCE[0]}"
fi
export RESEARCH_ROOT="$(cd "$(dirname "$_research_source")/.." && pwd)"
export ASAHI_ROOT="${ASAHI_ROOT:-$RESEARCH_ROOT/local}"
. "$RESEARCH_ROOT/setup/env.sh"
export M1N1_CHECKOUT="$ASAHI_ROOT/m1n1"
export VEL2_CHECKOUT="$ASAHI_ROOT/m1n1-vel2"
export RUSTUP_TOOLCHAIN=1.98.1
. "$ASAHI_ROOT/venv/bin/activate"
unset _research_source
