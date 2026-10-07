"""
BHRAM Telemetry — Web Collector
=================================

Instruments the Flask web application to produce canonical BHRAM events
for every HTTP request received by the honeypot web server.

This module provides:
  1. WebCollector.from_request_dict() — normalize a single HTTP request dict
  2. WebTelemetryMiddleware — WSGI middleware to auto-instrument Flask
  3. Helpers for credential attempt and suspicious path detection

SUSPICIOUS PATTERNS:
  Paths that suggest active exploitation, credential stuffing, or recon.

INSTRUMENTATION:
  Add to Flask app:
    from bhram.telemetry.collectors.web import WebTelemetryMiddleware
    app.wsgi_app = WebTelemetryMiddleware(app.wsgi_app, emit_fn=my_emit)
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

from bhram.telemetry.schemas import (
    ActorInfo,
    CanonicalEvent,
    EventDetail,
    EventSource,
    TargetInfo,
)

logger = logging.getLogger("bhram.telemetry.web")

# ── Suspicious path patterns ─────────────────────────────────────────────────

_SUSPICIOUS_PATHS = [
    re.compile(r"/(admin|wp-admin|phpmyadmin|adminer|manager|console)", re.I),
    re.compile(r"\.(env|git|htaccess|config|bak|sql|log|backup)$", re.I),
    re.compile(r"/(etc/passwd|etc/shadow|proc/self|var/log)", re.I),
    re.compile(r"/(\.\./)"),
    re.compile(r"/(phpinfo|shell|cmd|exec|eval)", re.I),
    re.compile(r"/(xmlrpc\.php|wp-login\.php|setup\.php)", re.I),
]

_AUTH_PATHS = {"/login", "/api/login", "/auth", "/signin", "/employee/auth"}
_CRED_FORM_FIELDS = {"username", "password", "passwd", "email", "user"}


def _is_suspicious(path: str) -> bool:
    return any(p.search(path) for p in _SUSPICIOUS_PATHS)


def _severity_from_request(
    method: str, path: str, status_code: int, is_auth: bool, is_suspicious: bool
) -> str:
    if is_suspicious:
        return "high"
    if is_auth:
        return "critical" if status_code < 400 else "medium"
    if method in ("POST", "PUT", "DELETE") and status_code < 400:
        return "medium"
    return "low"


# ── Core normalization ────────────────────────────────────────────────────────

class WebCollector:
    """Normalizes raw HTTP request data into canonical BHRAM events."""

    SOURCE = EventSource(component="web", version="flask-3.x", host="bhram_web")

    @classmethod
    def from_request_dict(cls, req: Dict[str, Any]) -> CanonicalEvent:
        """
        Convert a dict of HTTP request fields to a CanonicalEvent.

        Expected keys:
          source_ip, method, path, status_code, user_agent,
          session_id, authenticated_user, form_data, query_string,
          timestamp, destination_host, destination_port
        """
        path = req.get("path", "/")
        method = req.get("method", "GET").upper()
        status_code = req.get("status_code", 200)
        source_ip = req.get("source_ip", "")
        user_agent = req.get("user_agent", "")
        session_id = req.get("session_id")
        auth_user = req.get("authenticated_user")
        form_data = req.get("form_data", {}) or {}
        ts_raw = req.get("timestamp")

        ts = (
            datetime.fromisoformat(ts_raw) if ts_raw
            else datetime.now(timezone.utc)
        )
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        is_auth_path = path.lower().rstrip("/") in _AUTH_PATHS
        is_cred_submit = bool(
            is_auth_path and method == "POST" and
            _CRED_FORM_FIELDS.intersection(form_data.keys())
        )
        is_suspicious = _is_suspicious(path)

        # Determine event type
        if is_cred_submit:
            event_type = "credential_attempt"
            category = "auth"
        elif is_suspicious:
            event_type = "honeypot_detection_attempt"
            category = "deception_trigger"
        else:
            event_type = "web_request"
            category = "http"

        action = f"{method} {path}"
        outcome = "success" if status_code < 400 else "failure"
        severity = _severity_from_request(method, path, status_code, is_auth_path, is_suspicious)

        return CanonicalEvent(
            timestamp=ts,
            session_id=session_id,
            source_ip=source_ip,
            destination_host=req.get("destination_host", "bhram_web"),
            destination_port=req.get("destination_port", 8080),
            source=cls.SOURCE,
            event=EventDetail(
                type=event_type,
                category=category,
                action=action,
                outcome=outcome,
            ),
            actor=ActorInfo(
                username=auth_user,
                user_agent=user_agent,
                session_id=session_id,
            ),
            target=TargetInfo(
                host=req.get("destination_host", "bhram_web"),
                port=req.get("destination_port", 8080),
                service="http",
                path=path,
            ),
            severity=severity,
            raw_data=req,
            metadata={
                "status_code": status_code,
                "method": method,
                "query_string": req.get("query_string", ""),
                "is_suspicious_path": is_suspicious,
                "is_credential_attempt": is_cred_submit,
                "referer": req.get("referer", ""),
                "content_length": req.get("content_length", 0),
            },
        )


# ── Flask / WSGI instrumentation ──────────────────────────────────────────────

class WebTelemetryMiddleware:
    """
    WSGI middleware that wraps the Flask app to emit a CanonicalEvent
    for every HTTP request processed.

    Usage:
        from bhram.telemetry.collectors.web import WebTelemetryMiddleware

        def emit(event: CanonicalEvent):
            # send to normalizer / storage pipeline
            ...

        app.wsgi_app = WebTelemetryMiddleware(app.wsgi_app, emit_fn=emit)
    """

    def __init__(self, wsgi_app: Callable, emit_fn: Callable[[CanonicalEvent], None]):
        self.app = wsgi_app
        self.emit = emit_fn

    def __call__(self, environ: Dict, start_response: Callable) -> Iterable:
        source_ip = (
            environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
            or environ.get("REMOTE_ADDR", "")
        )
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        query = environ.get("QUERY_STRING", "")
        user_agent = environ.get("HTTP_USER_AGENT", "")
        content_length = environ.get("CONTENT_LENGTH", 0) or 0

        # Capture status code
        captured_status = [200]

        def _start_response(status: str, headers: list, *args):
            try:
                captured_status[0] = int(status.split(" ")[0])
            except (ValueError, IndexError):
                pass
            return start_response(status, headers, *args)

        response = self.app(environ, _start_response)

        try:
            req_dict = {
                "source_ip": source_ip,
                "method": method,
                "path": path,
                "status_code": captured_status[0],
                "user_agent": user_agent,
                "query_string": query,
                "content_length": int(content_length),
                "destination_host": environ.get("SERVER_NAME", "bhram_web"),
                "destination_port": int(environ.get("SERVER_PORT", 8080)),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            event = WebCollector.from_request_dict(req_dict)
            self.emit(event)
        except Exception as exc:
            logger.error("WebTelemetryMiddleware emit error: %s", exc)

        return response
