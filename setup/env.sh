# Source this after choosing ASAHI_ROOT; does not edit shell profiles.
export ASAHI_ROOT="${ASAHI_ROOT:-$HOME/asahi}"
export RUSTUP_HOME="$ASAHI_ROOT/toolchains/rustup"
export CARGO_HOME="$ASAHI_ROOT/toolchains/cargo"
export PATH="/opt/homebrew/opt/make/libexec/gnubin:/opt/homebrew/opt/rustup/bin:/opt/homebrew/bin:$PATH"
export HOMEBREW_NO_ANALYTICS=1
export PYTHONPYCACHEPREFIX="$ASAHI_ROOT/python-cache"
export LLDDIR=/opt/homebrew/opt/lld/bin/
