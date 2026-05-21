import json
import logging
from io import StringIO

from cerberus.core.logger import JsonFormatter, get_logger


def test_json_formatter_outputs_valid_json():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="cerberus.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    line = formatter.format(record)
    payload = json.loads(line)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "cerberus.test"
    assert payload["message"] == "hello world"
    assert "timestamp" in payload


def test_get_logger_writes_to_stream():
    stream = StringIO()
    logger = get_logger("cerberus.tests.unit", stream=stream)
    logger.info("payload", extra={"event_id": "abc-123"})
    payload = json.loads(stream.getvalue().splitlines()[-1])
    assert payload["message"] == "payload"
    assert payload["event_id"] == "abc-123"


def test_get_logger_is_idempotent():
    a = get_logger("cerberus.tests.unit")
    b = get_logger("cerberus.tests.unit")
    assert a is b
    assert len(a.handlers) == len(b.handlers)
