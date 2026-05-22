from cerberus.service.ipc import (
    InMemoryTransport,
    IpcClient,
    IpcDispatcher,
    IpcServer,
)


def _dispatcher():
    state = {"mode": "dry_run"}

    def status(args):
        return {"events": 3, "findings": 1, "mode": state["mode"]}

    def set_mode(args):
        state["mode"] = args["mode"]
        return {"mode": state["mode"]}

    d = IpcDispatcher()
    d.register("status", status)
    d.register("mode", set_mode)
    return d, state


def test_dispatcher_routes_command():
    d, _ = _dispatcher()
    resp = d.handle({"command": "status", "args": {}})
    assert resp["ok"] is True
    assert resp["data"]["events"] == 3


def test_dispatcher_unknown_command():
    d, _ = _dispatcher()
    resp = d.handle({"command": "nope", "args": {}})
    assert resp["ok"] is False
    assert "unknown" in resp["error"].lower()


def test_dispatcher_handler_exception_is_caught():
    d = IpcDispatcher()
    def boom(args):
        raise RuntimeError("x")
    d.register("boom", boom)
    resp = d.handle({"command": "boom", "args": {}})
    assert resp["ok"] is False
    assert resp["error"]


def test_inmemory_roundtrip_client_server():
    d, _state = _dispatcher()
    transport = InMemoryTransport()
    server = IpcServer(transport, d)
    server.start()
    client = IpcClient(transport)
    r1 = client.request("status")
    assert r1["ok"] and r1["data"]["mode"] == "dry_run"
    r2 = client.request("mode", mode="auto_all")
    assert r2["ok"] and r2["data"]["mode"] == "auto_all"
    r3 = client.request("status")
    assert r3["data"]["mode"] == "auto_all"
    server.stop()


def test_server_handles_invalid_json():
    import json
    d, _ = _dispatcher()
    transport = InMemoryTransport()
    IpcServer(transport, d).start()
    raw = transport.round_trip("{not json")
    assert json.loads(raw)["ok"] is False
