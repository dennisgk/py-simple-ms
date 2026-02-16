#!/usr/bin/env python3
import contextlib
import io
import json
import sys
import traceback


GLOBAL_SCOPE = {"__name__": "__main__"}
ORIG_STDOUT = sys.stdout


def respond(obj: dict) -> None:
    ORIG_STDOUT.write(json.dumps(obj) + "\n")
    ORIG_STDOUT.flush()


class StreamEmitter(io.TextIOBase):
    def __init__(self, stream_name: str) -> None:
        self.stream_name = stream_name

    def write(self, s: str) -> int:
        if not s:
            return 0
        respond({"type": "stream", "stream": self.stream_name, "data": s})
        return len(s)

    def flush(self) -> None:
        return


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue

    try:
        msg = json.loads(line)
        if msg.get("type") != "exec":
            respond({"type": "error", "error": "unknown worker msg"})
            continue

        code = str(msg.get("code", ""))
        ok = True
        tb = ""

        with contextlib.redirect_stdout(StreamEmitter("stdout")), contextlib.redirect_stderr(StreamEmitter("stderr")):
            try:
                exec(code, GLOBAL_SCOPE, GLOBAL_SCOPE)
            except Exception:
                ok = False
                tb = traceback.format_exc()
                # Mirror uncaught execution errors to streamed stderr.
                respond({"type": "stream", "stream": "stderr", "data": tb})

        respond({"type": "exec_result", "ok": ok, "traceback": tb})
    except Exception:
        respond({"type": "error", "error": "bad json or worker exception", "traceback": traceback.format_exc()})
