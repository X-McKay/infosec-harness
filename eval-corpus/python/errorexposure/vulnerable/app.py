import json
import os
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

# Loaded from the environment in production; the code keeps it in module state.
DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://report:changeme@db.internal/reports")


def load_report(report_id: str) -> dict:
    connection_string = DATABASE_URL
    if not report_id.isdigit():
        raise ValueError(f"bad report id {report_id!r} for {connection_string}")
    return {"id": int(report_id), "rows": []}


class ReportHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Serve /report?id=N.

        VULNERABLE: on any error the full traceback, including local values formatted
        into the exception, is returned to the caller.
        """
        try:
            report_id = self.path.partition("id=")[2]
            body = json.dumps(load_report(report_id)).encode()
            self.send_response(200)
        except Exception:
            body = traceback.format_exc().encode()
            self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def make_server(port: int = 0) -> HTTPServer:
    return HTTPServer(("127.0.0.1", port), ReportHandler)
