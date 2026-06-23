#!/usr/bin/env python3
"""Start the CPE Editor Flask app with production-oriented Gunicorn defaults.

The script keeps the existing dual-stack IPv4/IPv6 socket setup while adding
safe, environment-configurable Gunicorn defaults for higher concurrency and
worker recycling. Any arguments passed to this script are appended last, so they
can override these defaults when needed.
"""

from __future__ import annotations

import multiprocessing
import os
import socket
import sys
import tempfile
from collections.abc import Iterable, Sequence

DEFAULT_PORT = 5000
DEFAULT_WORKER_CLASS = "gthread"
DEFAULT_THREADS = 4
DEFAULT_TIMEOUT = 60
DEFAULT_GRACEFUL_TIMEOUT = 30
DEFAULT_KEEPALIVE = 5
DEFAULT_BACKLOG = 2048
DEFAULT_MAX_REQUESTS = 1000
DEFAULT_MAX_REQUESTS_JITTER = 100
DEFAULT_ACCESS_LOG_FORMAT = (
    '%(h)s %({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s '
    '"%(f)s" "%(a)s"'
)


def _env_int(name: str, default: int, *, minimum: int | None = None) -> int:
    """Return a validated integer environment setting."""

    raw_value = os.environ.get(name)
    if raw_value is None or raw_value.strip() == "":
        return default

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer, got {raw_value!r}") from exc

    if minimum is not None and value < minimum:
        raise SystemExit(f"{name} must be at least {minimum}, got {value}")

    return value


def _default_workers() -> int:
    """Return a conservative Gunicorn worker count based on available CPUs."""

    return (multiprocessing.cpu_count() * 2) + 1


def _listen_socket(family: socket.AddressFamily, host: str, port: int) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    sock.set_inheritable(True)
    return sock


def _open_listen_sockets(
    port: int, host_ipv4: str, host_ipv6: str
) -> list[socket.socket]:
    """Open configured listening sockets. IPv6 can be disabled by clearing HOST_IPV6."""

    sockets = [_listen_socket(socket.AF_INET, host_ipv4, port)]
    if not host_ipv6:
        return sockets

    try:
        sockets.append(_listen_socket(socket.AF_INET6, host_ipv6, port))
    except OSError as exc:
        sockets[0].close()
        raise SystemExit(
            f"Unable to bind IPv6 host {host_ipv6!r} on port {port}: {exc}"
        ) from exc
    return sockets


def _worker_tmp_dir() -> str:
    """Return a safe worker temp directory, preferring shared memory when available."""

    return os.environ.get(
        "GUNICORN_WORKER_TMP_DIR",
        "/dev/shm" if os.path.isdir("/dev/shm") else tempfile.gettempdir(),
    )


def build_gunicorn_command(
    sockets: Iterable[socket.socket], extra_args: Sequence[str]
) -> list[str]:
    """Build the Gunicorn command with production-ready, overridable defaults."""

    command = ["gunicorn"]
    for sock in sockets:
        command.extend(["--bind", f"fd://{sock.fileno()}"])

    command.extend(
        [
            "--workers",
            str(_env_int("WEB_CONCURRENCY", _default_workers(), minimum=1)),
            "--worker-class",
            os.environ.get("GUNICORN_WORKER_CLASS", DEFAULT_WORKER_CLASS),
            "--threads",
            str(_env_int("GUNICORN_THREADS", DEFAULT_THREADS, minimum=1)),
            "--timeout",
            str(_env_int("GUNICORN_TIMEOUT", DEFAULT_TIMEOUT, minimum=1)),
            "--graceful-timeout",
            str(
                _env_int(
                    "GUNICORN_GRACEFUL_TIMEOUT",
                    DEFAULT_GRACEFUL_TIMEOUT,
                    minimum=1,
                )
            ),
            "--keep-alive",
            str(_env_int("GUNICORN_KEEPALIVE", DEFAULT_KEEPALIVE, minimum=1)),
            "--backlog",
            str(_env_int("GUNICORN_BACKLOG", DEFAULT_BACKLOG, minimum=1)),
            "--max-requests",
            str(_env_int("GUNICORN_MAX_REQUESTS", DEFAULT_MAX_REQUESTS, minimum=0)),
            "--max-requests-jitter",
            str(
                _env_int(
                    "GUNICORN_MAX_REQUESTS_JITTER",
                    DEFAULT_MAX_REQUESTS_JITTER,
                    minimum=0,
                )
            ),
            "--worker-tmp-dir",
            _worker_tmp_dir(),
            "--access-logfile",
            os.environ.get("GUNICORN_ACCESS_LOGFILE", "-"),
            "--access-logformat",
            os.environ.get("GUNICORN_ACCESS_LOGFORMAT", DEFAULT_ACCESS_LOG_FORMAT),
            "--error-logfile",
            os.environ.get("GUNICORN_ERROR_LOGFILE", "-"),
            "wsgi:app",
            *extra_args,
        ]
    )
    return command


def main() -> None:
    port = _env_int("PORT", DEFAULT_PORT, minimum=1)
    host_ipv4 = os.environ.get("HOST_IPV4", "0.0.0.0")
    host_ipv6 = os.environ.get("HOST_IPV6", "::")

    sockets = _open_listen_sockets(port, host_ipv4, host_ipv6)
    command = build_gunicorn_command(sockets, sys.argv[1:])
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
