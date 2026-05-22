from unittest.mock import MagicMock, patch

from cerberus.response.actions import Action
from cerberus.response.executor import SystemExecutor


def _ex(tmp_path):
    return SystemExecutor(quarantine_dir=tmp_path / "q")


def test_build_block_ip_valid(tmp_path):
    b = _ex(tmp_path).build(Action(type="block_ip", params={"ip": "9.9.9.9"}))
    assert b.valid is True
    assert "9.9.9.9" in b.command
    assert b.reverted_command and "delete" in b.reverted_command


def test_build_block_ip_rejects_bad_ip(tmp_path):
    b = _ex(tmp_path).build(Action(type="block_ip", params={"ip": "9.9.9.9; rm -rf /"}))
    assert b.valid is False
    assert b.reason == "invalid_ip"


def test_build_stop_service_rejects_bad_name(tmp_path):
    b = _ex(tmp_path).build(Action(type="stop_service", params={"name": "svc & evil"}))
    assert b.valid is False


def test_build_disable_user_rejects_bad_name(tmp_path):
    b = _ex(tmp_path).build(Action(type="disable_user", params={"username": "a|b"}))
    assert b.valid is False


def test_run_block_ip_uses_subprocess_args_list(tmp_path):
    ex = _ex(tmp_path)
    with patch("cerberus.response.executor.subprocess.run") as mrun:
        mrun.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        res = ex.run(Action(type="block_ip", params={"ip": "9.9.9.9"}))
    assert res.executed is True
    assert res.success is True
    args, kwargs = mrun.call_args
    assert isinstance(args[0], list)        # args list, NO shell string
    assert kwargs.get("shell", False) is False


def test_run_invalid_does_not_call_subprocess(tmp_path):
    ex = _ex(tmp_path)
    with patch("cerberus.response.executor.subprocess.run") as mrun:
        res = ex.run(Action(type="block_ip", params={"ip": "bad ip"}))
    assert res.executed is False
    assert res.success is False
    mrun.assert_not_called()


def test_run_kill_pid_uses_psutil(tmp_path):
    ex = _ex(tmp_path)
    with patch("cerberus.response.executor.psutil.Process") as mproc:
        inst = mproc.return_value
        inst.terminate.return_value = None
        res = ex.run(Action(type="kill_pid", params={"pid": 4892}))
    assert res.executed is True
    inst.terminate.assert_called_once()


def test_revert_kill_pid_not_revertible(tmp_path):
    res = _ex(tmp_path).revert(Action(type="kill_pid", params={"pid": 1}))
    assert res.success is False
    assert res.reason == "not_revertible"


def test_revert_block_ip_runs_delete(tmp_path):
    ex = _ex(tmp_path)
    with patch("cerberus.response.executor.subprocess.run") as mrun:
        mrun.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        res = ex.revert(Action(type="block_ip", params={"ip": "9.9.9.9"}))
    assert res.executed is True
    assert "delete" in res.command
