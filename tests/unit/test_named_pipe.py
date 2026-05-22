import pytest

from cerberus.service.controller import ForegroundServiceController, ServiceController
from cerberus.service.named_pipe import IpcUnavailable, NamedPipeTransport


def test_named_pipe_degrades_without_pywin32(monkeypatch):
    import cerberus.service.named_pipe as mod
    monkeypatch.setattr(mod, "_load_pywin32", lambda: None)
    t = NamedPipeTransport(pipe_name=r"\\.\pipe\cerberus_test")
    assert t.available() is False


def test_named_pipe_round_trip_unavailable_raises(monkeypatch):
    import cerberus.service.named_pipe as mod
    monkeypatch.setattr(mod, "_load_pywin32", lambda: None)
    t = NamedPipeTransport(pipe_name=r"\\.\pipe\cerberus_test")
    with pytest.raises(IpcUnavailable):
        t.round_trip('{"command": "status", "args": {}}')


def test_named_pipe_bind_when_unavailable_is_noop(monkeypatch):
    import cerberus.service.named_pipe as mod
    monkeypatch.setattr(mod, "_load_pywin32", lambda: None)
    t = NamedPipeTransport(pipe_name=r"\\.\pipe\cerberus_test")
    t.bind(lambda raw: raw)   # no debe lanzar
    t.stop()


def test_foreground_controller_status():
    c: ServiceController = ForegroundServiceController()
    assert c.status() in ("stopped", "running")
    c.install()
    c.start()
    assert c.status() == "running"
    c.stop()
    assert c.status() == "stopped"
