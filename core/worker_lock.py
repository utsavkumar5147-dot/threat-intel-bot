import fcntl
import os
from contextlib import contextmanager
from pathlib import Path


LOCK_FILE = Path(__file__).resolve().parent.parent / "data" / "worker.lock"


@contextmanager
def single_worker():
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(
        LOCK_FILE,
        os.O_CREAT | os.O_RDWR,
        0o600
    )

    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(
                "Another Threat Intelligence Bot worker is already running."
            )

        yield

    finally:
        os.close(fd)
