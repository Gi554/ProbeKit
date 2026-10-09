"""Optional native comparator with an equivalent Python fallback."""
from collections import Counter
import ctypes
import os
from pathlib import Path
import sys


def python_similarity(left: bytes, right: bytes) -> float:
    if left == right:
        return 1.0
    if min(len(left), len(right)) < 3:
        return 0.0
    a = Counter(left[i:i+3] for i in range(len(left) - 2))
    b = Counter(right[i:i+3] for i in range(len(right) - 2))
    intersection = sum((a & b).values())
    return intersection / (len(left) + len(right) - 4 - intersection)


_function = None
_extension = ".dll" if sys.platform == "win32" else ".so"
_path = Path(os.environ.get("PROBEKIT_NATIVE_PATH", Path(__file__).parent / "_native" / ("probekit_compare" + _extension)))
try:
    _library = ctypes.CDLL(str(_path.resolve()))
    _function = _library.probekit_similarity
    _function.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    _function.restype = ctypes.c_double
except (OSError, AttributeError):
    pass


def similarity(left: bytes, right: bytes) -> float:
    if _function:
        score = _function(left, len(left), right, len(right))
        if 0 <= score <= 1:
            return score
    return python_similarity(left, right)


def backend() -> str:
    return "C++" if _function else "Python"
