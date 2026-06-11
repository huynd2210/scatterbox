"""scatterbox daemon: a thin FastAPI shell over core/scatterbox.

The daemon owns nothing the CLI doesn't — same register, same vault, same
pipeline functions (PLAN.md §4: one code path). What it adds is the serving
shape the web explorer needs: HTTP endpoints that answer instantly from the
local index, a background job queue so provider I/O never blocks a request,
and a WebSocket feed of job progress and health events.
"""

from scatterbox_daemon.app import create_app

__all__ = ["create_app"]
