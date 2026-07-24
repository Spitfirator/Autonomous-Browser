#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
EXTERNAL_ROOT="${WASP_EXTERNAL_ROOT:-$WORKSPACE_ROOT/.wasp}"
WASP_ROOT="${WASP_ROOT:-$EXTERNAL_ROOT/vendor/wasp}"
VENV="${WASP_VENV:-$EXTERNAL_ROOT/venv}"
WASP_COMMIT="ffee6f41fde76acd14bd792db442479c506260c2"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$EXTERNAL_ROOT/cache/uv}"
export UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-$EXTERNAL_ROOT/python}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$EXTERNAL_ROOT/browsers}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$EXTERNAL_ROOT/cache}"
export MPLCONFIGDIR="${MPLCONFIGDIR:-$EXTERNAL_ROOT/cache/matplotlib}"
export HF_HOME="${HF_HOME:-$EXTERNAL_ROOT/cache/huggingface}"
export NLTK_DATA="${NLTK_DATA:-$EXTERNAL_ROOT/nltk_data}"

mkdir -p \
	"$EXTERNAL_ROOT/vendor" \
	"$UV_CACHE_DIR" \
	"$UV_PYTHON_INSTALL_DIR" \
	"$PLAYWRIGHT_BROWSERS_PATH" \
	"$MPLCONFIGDIR" \
	"$HF_HOME" \
	"$NLTK_DATA"

if [ ! -d "$WASP_ROOT/.git" ]; then
	git clone --filter=blob:none https://github.com/facebookresearch/wasp.git "$WASP_ROOT"
fi

git -C "$WASP_ROOT" fetch --quiet origin "$WASP_COMMIT"
git -C "$WASP_ROOT" checkout --quiet "$WASP_COMMIT"

uv python install 3.10 --no-bin
if [ ! -x "$VENV/bin/python" ]; then
	uv venv "$VENV" --python 3.10
fi

# The official VisualWebArena requirements install CUDA/Torch/captioning
# packages that Sentinel does not use. This smaller environment contains the
# official injector, login, final-oracle, and optional action-classifier
# dependencies while BrowserUse itself remains in browser-use/.venv.
uv pip install --python "$VENV/bin/python" \
	-r "$WASP_ROOT/webarena_prompt_injections/requirements.txt" \
	aiolimiter beartype evaluate gymnasium matplotlib nltk pillow scikit-image \
	text-generation tiktoken transformers
uv pip install --python "$VENV/bin/python" --no-deps \
	--editable "$WASP_ROOT/visualwebarena"

"$VENV/bin/python" -c \
	"import nltk; nltk.download('punkt', download_dir='$NLTK_DATA', quiet=True); nltk.download('punkt_tab', download_dir='$NLTK_DATA', quiet=True)"
"$VENV/bin/playwright" install chromium

echo "WASP source: $WASP_ROOT"
echo "Pinned commit: $(git -C "$WASP_ROOT" rev-parse HEAD)"
echo "WASP evaluator Python: $VENV/bin/python"
echo "Next: copy wasp.local.env.example to wasp.local.env, establish the SSH forwards, then run preflight."
