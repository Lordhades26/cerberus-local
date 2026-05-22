from cerberus.service.controller import (
    ForegroundServiceController,
    Win32ServiceController,
)


def test_install_argv_uses_sc_create():
    c = Win32ServiceController(service_name="Cerberus", python_exe="py.exe",
                               script="C:\\svc.py")
    argv = c.build_install_argv()
    assert argv[0] == "sc" and argv[1] == "create" and "Cerberus" in argv


def test_start_stop_status_argv():
    c = Win32ServiceController(service_name="Cerberus", python_exe="py.exe", script="s")
    assert c.build_start_argv() == ["sc", "start", "Cerberus"]
    assert c.build_stop_argv() == ["sc", "stop", "Cerberus"]
    assert c.build_status_argv() == ["sc", "query", "Cerberus"]


def test_parse_sc_query_running():
    out = "SERVICE_NAME: Cerberus\n    STATE : 4  RUNNING\n"
    assert Win32ServiceController.parse_status(out) == "running"


def test_parse_sc_query_stopped():
    out = "SERVICE_NAME: Cerberus\n    STATE : 1  STOPPED\n"
    assert Win32ServiceController.parse_status(out) == "stopped"


def test_parse_sc_query_unknown():
    assert Win32ServiceController.parse_status("garbage") == "unknown"


def test_foreground_controller_still_works():
    c = ForegroundServiceController()
    c.start()
    assert c.status() == "running"
