from cerberus.response.rate_limiter import RateLimiter


def test_allows_under_global_limit():
    rl = RateLimiter(max_actions_per_minute=3, max_isolate_per_hour=1)
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is False   # 4ta excede 3/min


def test_isolate_host_hourly_limit():
    rl = RateLimiter(max_actions_per_minute=10, max_isolate_per_hour=1)
    assert rl.allow("isolate_host") is True
    assert rl.allow("isolate_host") is False   # 2da isolate en la hora


def test_global_window_eviction(monkeypatch):
    import cerberus.response.rate_limiter as mod
    t = {"now": 1000.0}
    monkeypatch.setattr(mod.time, "monotonic", lambda: t["now"])
    rl = RateLimiter(max_actions_per_minute=2, max_isolate_per_hour=5)
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is False
    t["now"] += 61      # avanza > 60s -> ventana se vacia
    assert rl.allow("kill_pid") is True
