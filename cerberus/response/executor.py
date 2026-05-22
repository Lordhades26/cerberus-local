from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import psutil

from cerberus.core.logger import get_logger
from cerberus.response.actions import Action, ActionResult

_log = get_logger("cerberus.response.executor")

_NAME_RE = re.compile(r"^[A-Za-z0-9_.\\\- ]+$")
_CMD_TIMEOUT = 15


@dataclass(frozen=True)
class _Built:
    command: str
    reverted_command: str | None
    valid: bool
    reason: str
    argv: list[str] | None = None
    revert_argv: list[str] | None = None


def _valid_ip(ip: object) -> str | None:
    try:
        return str(ipaddress.ip_address(str(ip)))
    except ValueError:
        return None


def _valid_name(name: object) -> str | None:
    s = str(name)
    return s if _NAME_RE.match(s) else None


class SystemExecutor:
    """Única capa que toca el SO. Mockeada en todos los tests.

    build() es puro (valida + arma comando). run()/revert() ejecutan.
    Anti-inyección: subprocess.run(list, shell=False) con inputs validados.
    """

    def __init__(self, quarantine_dir: Path | str) -> None:
        self._quarantine_dir = Path(quarantine_dir)

    # ---- build (puro) ----
    def build(self, action: Action) -> _Built:
        t = action.type
        p = action.params
        if t == "kill_pid":
            pid = p.get("pid")
            if not isinstance(pid, int) or pid < 0:
                return _Built("", None, False, "invalid_pid")
            return _Built(f"taskkill /F /T /PID {pid}", None, True, "ok",
                          argv=["taskkill", "/F", "/T", "/PID", str(pid)])
        if t == "block_ip":
            ip = _valid_ip(p.get("ip"))
            if ip is None:
                return _Built("", None, False, "invalid_ip")
            rule_name = f"Cerberus_block_{ip}"
            add = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip}"]
            dele = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            return _Built(" ".join(add), " ".join(dele), True, "ok",
                          argv=add, revert_argv=dele)
        if t == "stop_service":
            svc = _valid_name(p.get("name"))
            if svc is None:
                return _Built("", None, False, "invalid_service")
            return _Built(f"sc stop {svc}", f"sc start {svc}", True, "ok",
                          argv=["sc", "stop", svc], revert_argv=["sc", "start", svc])
        if t == "disable_user":
            user = _valid_name(p.get("username"))
            if user is None:
                return _Built("", None, False, "invalid_username")
            return _Built(f"net user {user} /active:no", f"net user {user} /active:yes",
                          True, "ok",
                          argv=["net", "user", user, "/active:no"],
                          revert_argv=["net", "user", user, "/active:yes"])
        if t == "isolate_host":
            iso_name = "Cerberus_isolate"
            add = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={iso_name}", "dir=out", "action=block", "remoteip=0.0.0.0/0"]
            dele = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={iso_name}"]
            return _Built(" ".join(add), " ".join(dele), True, "ok",
                          argv=add, revert_argv=dele)
        if t == "quarantine":
            raw = p.get("path")
            if not raw:
                return _Built("", None, False, "invalid_path")
            src = Path(str(raw))
            if not src.is_file():
                return _Built("", None, False, "path_not_a_file")
            dest = self._quarantine_dir / f"{src.name}.quarantined"
            return _Built(f"move {src} -> {dest}", f"move {dest} -> {src}", True, "ok")
        return _Built("", None, False, "unknown_action")

    # ---- run (ejecuta) ----
    def run(self, action: Action) -> ActionResult:
        built = self.build(action)
        if not built.valid:
            return ActionResult(action=action, executed=False, success=False, output="",
                                command=built.command, reverted_command=built.reverted_command,
                                reason=built.reason)
        try:
            if action.type == "kill_pid":
                success, output = self._kill_pid(int(action.params["pid"]))
            elif action.type == "quarantine":
                success, output = self._quarantine(Path(str(action.params["path"])))
            elif built.argv is not None:
                success, output = self._run_cmd(built.argv)
            else:
                return ActionResult(action=action, executed=False, success=False, output="",
                                    command=built.command, reverted_command=built.reverted_command,
                                    reason="not_executable")
        except Exception as exc:  # cualquier fallo del SO -> registrado, no rompe el pipeline
            _log.error("action_exec_error", extra={"action": action.type, "error": str(exc)})
            return ActionResult(action=action, executed=True, success=False, output=repr(exc),
                                command=built.command, reverted_command=built.reverted_command,
                                reason="exec_error")
        return ActionResult(action=action, executed=True, success=success, output=output,
                            command=built.command, reverted_command=built.reverted_command,
                            reason="authorized")

    # ---- revert (rollback) ----
    def revert(self, action: Action) -> ActionResult:
        built = self.build(action)
        if built.revert_argv is None and action.type != "quarantine":
            return ActionResult(action=action, executed=False, success=False, output="",
                                command=built.reverted_command or "",
                                reverted_command=None, reason="not_revertible")
        try:
            if action.type == "quarantine":
                success, output = (False, "manual_restore_required")
            else:
                assert built.revert_argv is not None
                success, output = self._run_cmd(built.revert_argv)
        except Exception as exc:
            return ActionResult(action=action, executed=True, success=False, output=repr(exc),
                                command=built.reverted_command or "", reverted_command=None,
                                reason="revert_error")
        return ActionResult(action=action, executed=True, success=success, output=output,
                            command=built.reverted_command or "", reverted_command=None,
                            reason="reverted")

    # ---- low-level (mockeado en tests) ----
    @staticmethod
    def _run_cmd(argv: list[str]) -> tuple[bool, str]:
        proc = subprocess.run(argv, shell=False, capture_output=True, text=True,
                              timeout=_CMD_TIMEOUT)
        return proc.returncode == 0, (proc.stdout or proc.stderr or "")

    @staticmethod
    def _kill_pid(pid: int) -> tuple[bool, str]:
        try:
            psutil.Process(pid).terminate()
            return True, f"terminated {pid}"
        except Exception:
            return SystemExecutor._run_cmd(["taskkill", "/F", "/T", "/PID", str(pid)])

    def _quarantine(self, src: Path) -> tuple[bool, str]:
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = self._quarantine_dir / f"{src.name}.quarantined"
        shutil.move(str(src), str(dest))
        return True, f"quarantined to {dest}"
