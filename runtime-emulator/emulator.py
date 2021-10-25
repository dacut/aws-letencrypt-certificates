#!/usr/bin/env python3
from dataclasses import dataclass
import json
from io import BytesIO
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging import basicConfig, getLogger, DEBUG
from threading import Condition
from time import time
from typing import Any, Dict, List, Optional
from uuid import uuid4


RUNTIME_INVOCATION = "/2018-06-01/runtime/invocation/"


log = getLogger(__name__)


def request_available():
    global pending_requests
    return bool(pending_requests)


@dataclass
class LambdaRequest:
    request_id: str
    request: bytes
    response_code: Optional[int]
    response: Optional[bytes]


pending_requests: List[LambdaRequest] = []
pending_request_wait = Condition()

inflight_requests: Dict[str, LambdaRequest] = {}
finished_request_wait = Condition()


class LambdaRuntimeEmulatorHandler(BaseHTTPRequestHandler):
    server_version = "LambdaRuntimeEmulator/0.1"
    error_content_type = "application/json"

    def do_GET(self):
        if self.path == "/2018-06-01/runtime/invocation/next":
            return self.handle_next_invocation()

        log.error("GET %s not found", self.path)
        error = {"Error": {"Code": "NotFound", "Message": "Path not found for method GET"}}
        self.send_json_response(HTTPStatus.NOT_FOUND, error)

    def do_POST(self):
        log.info("POST %s", self.path)
        return self.handle_post_or_put()

    def do_PUT(self):
        log.info("PUT %s", self.path)
        return self.handle_post_or_put()

    def handle_post_or_put(self):
        if self.path == "/2018-06-01/runtime/init/error":
            return self.handle_runtime_init_error()
        elif self.path.startswith(RUNTIME_INVOCATION):
            parts = self.path[len(RUNTIME_INVOCATION) :].split("/")
            if len(parts) == 2 and parts[1] in ("response", "error"):
                return self.handle_invocation_response(request_id=parts[0], response_type=parts[2])
        elif self.path == "/invoke":
            return self.handle_invoke()

        # Unknown path
        error = {"Error": {"Code": "NotFound", "Message": "Path not found"}}
        self.send_json_response(HTTPStatus.NOT_FOUND, error)

    def handle_runtime_init_error(self):
        body = self.read_request_body().decode("utf-8", strict=False)
        log.error("Runtime initialization failed: %s", body)
        self.send_json_response(HTTPStatus.OK, {})

    def handle_invoke(self):
        global inflight_requests, finished_request_wait, pending_request_wait, pending_requests

        body = self.read_request_body()
        request_id = str(uuid4())

        lr = LambdaRequest(request_id=request_id, request=body, response_code=None, response=None)

        def request_done():
            nonlocal lr
            return lr.response is not None

        with finished_request_wait:
            inflight_requests[request_id] = lr

            with pending_request_wait:
                pending_requests.append(lr)
                pending_request_wait.notify(n=1)

            finished_request_wait.wait_for(request_done)

        self.send_response(lr.response_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(lr.response)))
        self.end_headers()
        self.send_body(lr.response)

    def handle_next_invocation(self) -> None:
        global inflight_requests, finished_request_wait, pending_request_wait, pending_requests

        with pending_request_wait:
            while True:
                pending_request_wait.wait_for(request_available)
                try:
                    lr = pending_requests.pop()
                    break
                except IndexError:
                    continue

        # Send this request to the Lambda function
        self.send_response(HTTPStatus.OK)
        self.send_header("Lambda-Runtime-Aws-Request-Id", lr.request_id)
        self.send_header("Lambda-Runtime-Deadline-Ms", str(int((time() + 15 * 60) * 1000)))  # 15 minutes from now
        self.send_header("Lambda-Runtime-Invoked-Function-Arn", "arn:aws:lambda:us-west-2:123456789012:function:Test")
        self.send_header(
            "Lambda-Runtime-Trace-Id", "Root=1-5bef4de7-ad49b0e87f6ef6c87fc2e700;Parent=9a9197af755a6419;Sampled=1"
        )
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(lr.request)))
        self.end_headers()
        self.send_body(lr.request)

    def handle_invocation_response(self, request_id: str, response_type: str) -> None:
        global inflight_requests, finished_request_wait, pending_request_wait, pending_requests

        response = self.read_request_body()

        with finished_request_wait:
            try:
                lr = inflight_requests.pop(request_id)
            except KeyError:
                error = {"Error": {"Code": "NotFound", "Message": "RequestId not found", "RequestId": request_id}}
                return self.send_json_response(HTTPStatus.NOT_FOUND, error)

            lr.response_code = HTTPStatus.OK if response_type == "response" else HTTPStatus.INTERNAL_SERVER_ERROR
            lr.response = response

            finished_request_wait.notify_all()

        self.send_json_response(HTTPStatus.OK, {})

    def send_json_response(self, code: HTTPStatus, error: Dict[str, Any]) -> None:
        error_body = json.dumps(error).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(error_body)))
        self.end_headers()
        self.send_body(error_body)

    def read_request_body(self) -> bytes:
        content_length_str = self.headers.get("content-length")

        if content_length_str is None:
            return self.rfile.read()

        body = BytesIO()
        n_read = 0
        content_length = int(content_length_str)
        while n_read < content_length:
            chunk = self.rfile.read(content_length - n_read)
            if len(chunk) == 0:
                log.error("Short read from %s on %s to %s", self.client_address, self.command, self.path)
                break

            body.write(chunk)
            n_read += len(chunk)

        return body.getvalue()

    def send_body(self, body_bytes: bytes) -> None:
        while body_bytes:
            n_written = self.wfile.write(body_bytes)
            if n_written <= 0 or n_written == len(body_bytes):
                break

            body_bytes = body_bytes[n_written:]


def main():
    basicConfig(level=DEBUG, format="%(asctime)s [%(levelname)s] %(name)s %(filename)s %(lineno)d: %(message)s")
    root_logger = getLogger()
    root_logger.handlers[0].formatter.default_msec_format = "%s.%03d"

    server = ThreadingHTTPServer(("127.0.0.1", 9090), LambdaRuntimeEmulatorHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
