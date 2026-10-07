"""
BHRAM Telemetry — Network Telemetry Adapter
=============================================

Provides an abstract interface for network telemetry so that:
  - In Part 2 (now): synthetic/generated network events work immediately
  - In Part 3+: Zeek can be plugged in by implementing ZeekAdapter

Architecture:
    NetworkTelemetryAdapter (abstract base)
        ├── SyntheticNetworkAdapter  ← used now for lab/testing
        └── ZeekAdapter              ← stub, ready for Zeek integration

The adapter interface is fixed. Zeek or any other network monitor
can be integrated by implementing the abstract methods without
changing any other part of the system.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

from bhram.telemetry.schemas import (
    ActorInfo,
    CanonicalEvent,
    EventDetail,
    EventSource,
    TargetInfo,
)

logger = logging.getLogger("bhram.telemetry.network")


# ── Abstract interface ────────────────────────────────────────────────────────

class NetworkTelemetryAdapter(ABC):
    """
    Abstract base class for all BHRAM network telemetry sources.

    Any network monitor (Zeek, Suricata, tcpdump parser, etc.) must
    implement these methods to integrate with the BHRAM telemetry pipeline.
    """

    @abstractmethod
    def parse_connection(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Parse a raw TCP/UDP connection log entry."""
        ...

    @abstractmethod
    def parse_dns(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Parse a raw DNS query/response log entry."""
        ...

    @abstractmethod
    def parse_http(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Parse a raw HTTP request/response log entry."""
        ...

    @abstractmethod
    def parse_scan(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Parse a port-scan or host-discovery event."""
        ...

    def collect(self) -> Generator[CanonicalEvent, None, None]:
        """
        Optionally override to yield a stream of events.
        Default: no-op generator.
        """
        return
        yield  # make it a generator


# ── Zeek adapter stub ─────────────────────────────────────────────────────────

class ZeekAdapter(NetworkTelemetryAdapter):
    """
    Stub Zeek adapter — ready for Part 3 integration.

    To activate: install Zeek and point log_dir at Zeek's log output.
    Implement parse_* methods to read Zeek TSV/JSON logs.
    """

    def __init__(self, log_dir: str = "/var/log/zeek/current"):
        self.log_dir = log_dir
        logger.info("ZeekAdapter initialized (stub) — log_dir: %s", log_dir)

    def parse_connection(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """
        Parse Zeek conn.log entry.
        Example Zeek fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
                             proto, duration, orig_bytes, resp_bytes, conn_state
        """
        # TODO: Implement when Zeek is deployed
        logger.debug("ZeekAdapter.parse_connection not yet implemented")
        return None

    def parse_dns(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Parse Zeek dns.log entry."""
        logger.debug("ZeekAdapter.parse_dns not yet implemented")
        return None

    def parse_http(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Parse Zeek http.log entry."""
        logger.debug("ZeekAdapter.parse_http not yet implemented")
        return None

    def parse_scan(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Parse Zeek notice.log scan alerts."""
        logger.debug("ZeekAdapter.parse_scan not yet implemented")
        return None


# ── Synthetic adapter (used for Part 2 lab/testing) ──────────────────────────

_NETWORK_SOURCE = EventSource(component="network", version="synthetic-1.0")


class SyntheticNetworkAdapter(NetworkTelemetryAdapter):
    """
    Synthetic network telemetry adapter.

    Accepts pre-built network event dicts and normalizes them.
    Used for:
      - Part 2 testing without live Zeek
      - Demo script event generation
      - CI/CD pipeline validation
    """

    def parse_connection(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Normalize a connection event dict."""
        src_ip = raw.get("src_ip", "")
        dst_ip = raw.get("dst_ip", "")
        dst_port = raw.get("dst_port")
        proto = raw.get("proto", "tcp").lower()
        ts_raw = raw.get("timestamp")
        ts = (
            datetime.fromisoformat(ts_raw).astimezone(timezone.utc)
            if ts_raw else datetime.now(timezone.utc)
        )

        return CanonicalEvent(
            timestamp=ts,
            session_id=raw.get("uid"),
            source_ip=src_ip,
            source_port=raw.get("src_port"),
            destination_host=dst_ip,
            destination_port=dst_port,
            source=_NETWORK_SOURCE,
            event=EventDetail(
                type="network_connection",
                category="network",
                action=f"{proto}:{src_ip}->{dst_ip}:{dst_port}",
                outcome=raw.get("conn_state", "unknown"),
            ),
            actor=ActorInfo(session_id=raw.get("uid")),
            target=TargetInfo(host=dst_ip, port=dst_port, service=proto),
            severity=raw.get("severity", "low"),
            raw_data=raw,
            metadata={
                "protocol": proto,
                "bytes_sent": raw.get("orig_bytes", 0),
                "bytes_recv": raw.get("resp_bytes", 0),
                "duration": raw.get("duration"),
            },
        )

    def parse_dns(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Normalize a DNS event dict."""
        return CanonicalEvent(
            session_id=raw.get("uid"),
            source_ip=raw.get("src_ip"),
            destination_host=raw.get("query", ""),
            source=_NETWORK_SOURCE,
            event=EventDetail(
                type="network_connection",
                category="network",
                action=f"dns:{raw.get('query', '')} type={raw.get('qtype', 'A')}",
                outcome="success" if raw.get("rcode", 0) == 0 else "failure",
            ),
            actor=ActorInfo(session_id=raw.get("uid")),
            target=TargetInfo(host=raw.get("query", ""), service="dns", port=53),
            severity="info",
            raw_data=raw,
            metadata={"dns_query": raw.get("query"), "qtype": raw.get("qtype", "A")},
        )

    def parse_http(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Normalize an HTTP network-layer event dict."""
        return CanonicalEvent(
            session_id=raw.get("uid"),
            source_ip=raw.get("src_ip"),
            destination_host=raw.get("host", raw.get("dst_ip", "")),
            destination_port=raw.get("dst_port", 80),
            source=_NETWORK_SOURCE,
            event=EventDetail(
                type="web_request",
                category="http",
                action=f"{raw.get('method','GET')} {raw.get('uri','/')}",
                outcome="success" if raw.get("status_code", 200) < 400 else "failure",
            ),
            actor=ActorInfo(
                user_agent=raw.get("user_agent"),
                session_id=raw.get("uid"),
            ),
            target=TargetInfo(
                host=raw.get("host", ""),
                port=raw.get("dst_port", 80),
                service="http",
                path=raw.get("uri", "/"),
            ),
            severity="low",
            raw_data=raw,
            metadata={
                "status_code": raw.get("status_code"),
                "method": raw.get("method"),
                "uri": raw.get("uri"),
            },
        )

    def parse_scan(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """Normalize a port scan event dict."""
        return CanonicalEvent(
            session_id=raw.get("uid"),
            source_ip=raw.get("src_ip"),
            destination_host=raw.get("dst_ip", ""),
            source=_NETWORK_SOURCE,
            event=EventDetail(
                type="port_scan",
                category="network",
                action=f"scan:{raw.get('src_ip')}→{raw.get('dst_ip')}:{raw.get('ports',[])}",
                outcome="detected",
            ),
            actor=ActorInfo(session_id=raw.get("uid")),
            target=TargetInfo(
                host=raw.get("dst_ip", ""),
                service="network",
            ),
            severity="medium",
            raw_data=raw,
            metadata={
                "ports_scanned": raw.get("ports", []),
                "scan_type": raw.get("scan_type", "tcp_syn"),
            },
        )
