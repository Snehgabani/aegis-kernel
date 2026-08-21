import os
import sys

# Resolve the in-repo aegis-kernel Python core without requiring installation.
_REPO_PY_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "python"))
_PKG_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

for _p in (_REPO_PY_CORE, _PKG_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
