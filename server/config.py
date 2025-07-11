import json
import os
import pathlib

# root dir is two levels up from this file
ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
VALUES_PATH = ROOT_DIR / "values.json"

# lazy load json config
_json_cache = {}
if VALUES_PATH.exists():
    try:
        with open(VALUES_PATH, "r") as f:
            _json_cache = json.load(f)
    except Exception:
        # ignore malformed json, act like empty config
        _json_cache = {}

def get(key: str, default=None):
    # prefer explicit values.json over environment to avoid accidental drift
    if key in _json_cache:
        return _json_cache[key]
    return os.getenv(key, default) 