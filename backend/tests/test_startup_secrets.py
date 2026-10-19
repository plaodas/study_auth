import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
_STRIP = (
    "SECRET_KEY",
    "CSRF_SECRET",
    "JWT_PRIVATE_KEY",
    "JWT_PRIVATE_KEY_PATH",
    "JWT_PUBLIC_KEY",
    "JWT_PUBLIC_KEY_PATH",
    "JWT_PUBLIC_KEYS_DIR",
    "JWT_USE_KEYS_DIR",
)


def _env_without(*keep_out: str, **extra: str) -> dict:
    env = os.environ.copy()
    for name in _STRIP:
        env.pop(name, None)
    for name in keep_out:
        env.pop(name, None)
    env.update(extra)
    env["PYTHONPATH"] = str(BACKEND)
    return env


@pytest.mark.parametrize(
    ("module", "needle", "extra"),
    [
        ("app.services.token_service", "SECRET_KEY", {}),
        ("app.services.csrf", "CSRF_SECRET", {}),
        ("app.services.auth_service", "JWT_PRIVATE_KEY", {"SECRET_KEY": "present-for-token-service"}),
    ],
)
def test_import_fails_when_secret_is_missing(module, needle, extra):
    proc = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=BACKEND,
        env=_env_without(**extra),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert needle in proc.stderr
