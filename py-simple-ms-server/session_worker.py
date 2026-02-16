#!/usr/bin/env python3
import ast
import asyncio
import contextlib
import io
import inspect
import json
import os
import sys
import traceback


GLOBAL_SCOPE = {"__name__": "__main__"}
ORIG_STDOUT = sys.stdout
ANSI_RED = "\x1b[31m"
ANSI_RESET = "\x1b[0m"


def respond(obj: dict) -> None:
    ORIG_STDOUT.write(json.dumps(obj) + "\n")
    ORIG_STDOUT.flush()


class StreamEmitter(io.TextIOBase):
    def __init__(self, stream_name: str) -> None:
        self.stream_name = stream_name
        self.encoding = "utf-8"

    def write(self, s: str) -> int:
        if not s:
            return 0
        respond({"type": "stream", "stream": self.stream_name, "data": s})
        return len(s)

    def flush(self) -> None:
        return

    def isatty(self) -> bool:
        # Encourage color-capable log formatters/libraries to keep ANSI output.
        return True


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

        # Ensure imports resolve from the session working directory.
        cwd = os.getcwd()
        if cwd not in sys.path:
            sys.path.insert(0, cwd)

        with contextlib.redirect_stdout(StreamEmitter("stdout")), contextlib.redirect_stderr(StreamEmitter("stderr")):
            try:
                compiled = compile(code, "<session_exec>", "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
                result = eval(compiled, GLOBAL_SCOPE, GLOBAL_SCOPE)
                if inspect.iscoroutine(result):
                    asyncio.run(result)
            except Exception:
                ok = False
                tb = traceback.format_exc()
                # Mirror uncaught execution errors to streamed stderr.
                respond({"type": "stream", "stream": "stderr", "data": f"{ANSI_RED}{tb}{ANSI_RESET}"})

        respond({"type": "exec_result", "ok": ok, "traceback": tb})
    except Exception:
        tb = traceback.format_exc()
        respond({"type": "stream", "stream": "stderr", "data": f"{ANSI_RED}{tb}{ANSI_RESET}"})
        respond({"type": "error", "error": "bad json or worker exception", "traceback": tb})
