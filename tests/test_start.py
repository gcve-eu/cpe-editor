import socket

import pytest

import start


class FakeSocket:
    def __init__(self, fileno):
        self._fileno = fileno

    def fileno(self):
        return self._fileno


def test_build_gunicorn_command_includes_production_defaults(monkeypatch):
    monkeypatch.setattr(start.multiprocessing, "cpu_count", lambda: 2)
    command = start.build_gunicorn_command(
        [FakeSocket(3), FakeSocket(4)], ["--workers", "9"]
    )

    assert command[:5] == ["gunicorn", "--bind", "fd://3", "--bind", "fd://4"]
    assert command[command.index("--workers") + 1] == "5"
    assert command[command.index("--worker-class") + 1] == "gthread"
    assert command[command.index("--threads") + 1] == "4"
    assert command[command.index("--backlog") + 1] == "2048"
    assert command[command.index("--max-requests") + 1] == "1000"
    assert command[-3:] == ["wsgi:app", "--workers", "9"]


def test_build_gunicorn_command_reads_environment(monkeypatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "6")
    monkeypatch.setenv("GUNICORN_THREADS", "8")
    monkeypatch.setenv("GUNICORN_WORKER_TMP_DIR", "/tmp")

    command = start.build_gunicorn_command([FakeSocket(3)], [])

    assert command[command.index("--workers") + 1] == "6"
    assert command[command.index("--threads") + 1] == "8"
    assert command[command.index("--worker-tmp-dir") + 1] == "/tmp"


def test_env_int_rejects_invalid_values(monkeypatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "0")

    with pytest.raises(SystemExit, match="WEB_CONCURRENCY must be at least 1"):
        start.build_gunicorn_command([FakeSocket(3)], [])


def test_open_listen_sockets_allows_ipv6_to_be_disabled(monkeypatch):
    calls = []

    def fake_listen_socket(family, host, port):
        calls.append((family, host, port))
        return FakeSocket(3)

    monkeypatch.setattr(start, "_listen_socket", fake_listen_socket)

    sockets = start._open_listen_sockets(8000, "0.0.0.0", "")

    assert len(sockets) == 1
    assert calls == [(socket.AF_INET, "0.0.0.0", 8000)]
