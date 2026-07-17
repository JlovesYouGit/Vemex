import json
import time
import hashlib
import os
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class TransportType(Enum):
    NETWORK = "network"
    BLUETOOTH = "Bluetooth"
    SERIAL = "serial"
    USB_IO = "USB_IO"


class ConnectionStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ESTABLISHED = "established"
    FAILED = "failed"
    DEGRADED = "degraded"


@dataclass
class ConnectionSpec:
    mac: Optional[str] = None
    port: Optional[int] = None
    established: bool = False
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED
    transport: Optional[TransportType] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RouteDecision:
    transport: TransportType
    connection_spec: ConnectionSpec
    reason: str
    confidence: float
    fallback_transports: List[TransportType]
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))


@dataclass
class SeedRecord:
    address: str
    line: int
    kind: str
    value: str
    value_sha256: str
    file_sha256: str
    origin: Optional[Dict[str, Any]] = None
    kernel_result: Optional[Dict[str, Any]] = None
    routed: bool = False
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))


class SeedGateIntegration:
    def __init__(self, base_path: Path, vemex_engine: Optional[Any] = None):
        self.base_path = base_path
        self.vemex_engine = vemex_engine
        self.seedgate_path = base_path / "SeedGate"
        self.tracker_file = self.seedgate_path / "data" / "tracker.json"
        self.config_file = base_path / ".seedgate_config.json"
        self.connections_file = base_path / ".seedgate_connections.json"
        self.routing_log_file = base_path / ".seedgate_routing_log.json"
        
        self.config: Dict[str, Any] = {}
        self.connections: Dict[str, ConnectionSpec] = {}
        self.routing_log: List[Dict[str, Any]] = []
        self.seeds: List[SeedRecord] = []
        self.kernel_results: Dict[str, Any] = {}
        
        self._load_data()
        self._init_default_config()
        self._init_default_connections()

    def _load_data(self) -> None:
        for file_path, attr_name in [
            (self.config_file, "config"),
            (self.connections_file, "connections"),
            (self.routing_log_file, "routing_log"),
        ]:
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        setattr(self, attr_name, json.load(f))
                except Exception:
                    pass
        
        if self.tracker_file.exists():
            try:
                with open(self.tracker_file, "r", encoding="utf-8") as f:
                    tracker = json.load(f)
                self.seeds = []
                for seed_data in tracker.get("seeds", []):
                    self.seeds.append(SeedRecord(
                        address=seed_data.get("address", ""),
                        line=seed_data.get("line", 0),
                        kind=seed_data.get("kind", ""),
                        value=seed_data.get("value", ""),
                        value_sha256=seed_data.get("value_sha256", ""),
                        file_sha256=seed_data.get("file_sha256", ""),
                        origin=seed_data.get("origin"),
                        kernel_result=seed_data.get("kernel"),
                        routed=seed_data.get("routed", False),
                    ))
                self.kernel_results = tracker.get("kernel_results", {})
            except Exception:
                pass

    def _save_data(self) -> None:
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2, default=str)
            with open(self.connections_file, "w", encoding="utf-8") as f:
                json.dump({k: asdict(v) for k, v in self.connections.items()}, f, indent=2, default=str)
            with open(self.routing_log_file, "w", encoding="utf-8") as f:
                json.dump(self.routing_log, f, indent=2, default=str)
        except Exception:
            pass

    def _init_default_config(self) -> None:
        if not self.config:
            self.config = {
                "auto_routing": True,
                "default_transport": TransportType.NETWORK.value,
                "connection_timeout": 10,
                "retry_attempts": 3,
                "routing_strategy": "adaptive",
                "security": {
                    "require_established_connection": True,
                    "validate_mac_format": True,
                    "max_payload_size": 65536,
                    "allowed_transports": [t.value for t in TransportType],
                },
                "model_routing_preferences": {
                    "claude": {"preferred_transport": TransportType.NETWORK.value, "priority": 1},
                    "gemini": {"preferred_transport": TransportType.NETWORK.value, "priority": 2},
                    "chatgpt": {"preferred_transport": TransportType.BLUETOOTH.value, "priority": 3},
                    "kimi": {"preferred_transport": TransportType.SERIAL.value, "priority": 4},
                },
            }
            self._save_data()

    def _init_default_connections(self) -> None:
        if not self.connections:
            self.connections = {
                "default_network": ConnectionSpec(
                    mac="00:00:00:00:00:00",
                    port=8080,
                    established=False,
                    status=ConnectionStatus.DISCONNECTED,
                    transport=TransportType.NETWORK,
                ).__dict__,
                "default_bluetooth": ConnectionSpec(
                    mac="00:00:00:00:00:00",
                    port=None,
                    established=False,
                    status=ConnectionStatus.DISCONNECTED,
                    transport=TransportType.BLUETOOTH,
                ).__dict__,
            }
            self._save_data()

    def get_available_transports(self) -> List[str]:
        return [t.value for t in TransportType]

    def register_connection(self, connection_id: str, connection_spec: ConnectionSpec) -> Dict[str, Any]:
        self.connections[connection_id] = asdict(connection_spec)
        self._save_data()
        return {"success": True, "connection_id": connection_id, "spec": asdict(connection_spec)}

    def establish_connection(self, connection_id: str, mac: str, port: int, transport: TransportType) -> Dict[str, Any]:
        if connection_id not in self.connections:
            return {"success": False, "error": "Connection not found"}
        
        spec = ConnectionSpec(
            mac=mac,
            port=port,
            established=True,
            status=ConnectionStatus.ESTABLISHED,
            transport=transport,
            metadata={"established_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")},
        )
        self.connections[connection_id] = asdict(spec)
        self._save_data()
        return {"success": True, "connection_id": connection_id, "status": "established", "spec": asdict(spec)}

    def get_connection(self, connection_id: str) -> Optional[ConnectionSpec]:
        data = self.connections.get(connection_id)
        if data:
            return ConnectionSpec(**data)
        return None

    def decide_transport(self, context: Dict[str, Any]) -> RouteDecision:
        preferences = self.config.get("model_routing_preferences", {})
        provider = context.get("provider", "unknown")
        model = context.get("model", "unknown")
        
        preferred_transport = TransportType.NETWORK
        reason = "default"
        confidence = 0.5
        fallbacks = [t for t in TransportType if t != preferred_transport]
        
        provider_prefs = preferences.get(provider, {})
        if provider_prefs:
            transport_str = provider_prefs.get("preferred_transport", preferred_transport.value)
            preferred_transport = TransportType(transport_str)
            reason = f"provider_preference:{provider}"
            confidence = 0.8
            fallbacks = [t for t in TransportType if t != preferred_transport]
        
        task_type = context.get("task_type", "general")
        if "high_bandwidth" in task_type or "video" in task_type:
            if TransportType.NETWORK not in fallbacks:
                fallbacks.insert(0, TransportType.NETWORK)
            reason = f"task_requirement:{task_type}"
            confidence = 0.7
        elif "low_power" in task_type or "background" in task_type:
            if TransportType.BLUETOOTH not in fallbacks:
                fallbacks.insert(0, TransportType.BLUETOOTH)
            reason = f"task_requirement:{task_type}"
            confidence = 0.7
        
        connection_id = context.get("connection_id", "default_network")
        connection = self.get_connection(connection_id)
        if connection and connection.established and connection.transport == preferred_transport:
            confidence = min(confidence + 0.15, 1.0)
            reason = f"{reason}:active_connection"
        
        return RouteDecision(
            transport=preferred_transport,
            connection_spec=connection or ConnectionSpec(),
            reason=reason,
            confidence=confidence,
            fallback_transports=fallbacks[:3],
        )

    def route_seed(self, seed: SeedRecord, connection_spec: ConnectionSpec, transport: TransportType) -> Dict[str, Any]:
        if not connection_spec.established:
            return {
                "snapshotId": f"snapshot_{seed.line}",
                "routed": False,
                "reason": "connection_not_established",
                "seed_value": seed.value,
                "transport": transport.value,
            }
        
        payload = {
            "seed_value": seed.value,
            "value_sha256": seed.value_sha256,
            "kind": seed.kind,
            "address": seed.address,
            "line": seed.line,
            "origin": seed.origin,
        }
        
        routing_log_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "seed_value": seed.value,
            "transport": transport.value,
            "connection": asdict(connection_spec),
            "payload_keys": sorted(list(payload.keys())),
            "routed": True,
            "reason": "auto_routed",
        }
        self.routing_log.append(routing_log_entry)
        if len(self.routing_log) > 10000:
            self.routing_log = self.routing_log[-10000:]
        self._save_data()
        
        return {
            "snapshotId": f"snapshot_{seed.line}",
            "routed": True,
            "transport": f"{transport.value}-stub",
            "mac": connection_spec.mac,
            "port": connection_spec.port,
            "seed_value": seed.value,
            "payload_keys": sorted(list(payload.keys())),
        }

    def process_seeds(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        context = context or {}
        if not self.seeds:
            return {"status": "no_seeds", "processed": 0}
        
        route_decision = self.decide_transport(context)
        connection = route_decision.connection_spec
        
        results = []
        routed_count = 0
        for seed in self.seeds[:100]:
            result = self.route_seed(seed, connection, route_decision.transport)
            results.append(result)
            if result.get("routed"):
                routed_count += 1
        
        return {
            "status": "completed",
            "processed": len(results),
            "routed": routed_count,
            "transport": route_decision.transport.value,
            "connection_id": context.get("connection_id", "default_network"),
            "reason": route_decision.reason,
            "confidence": route_decision.confidence,
            "results": results[:10],
        }

    def scan_directory(self, directory: Path, extensions: Optional[List[str]] = None) -> Dict[str, Any]:
        if not directory.exists():
            return {"success": False, "error": "Directory does not exist"}
        
        patterns = [
            (r"\b(?:seed|SEED)\s*[:=]\s*(-?\d+|0x[0-9a-fA-F]+)\b", "assign_int"),
            (r"(?:random|np\.random|rng)\.seed\s*\(\s*(-?\d+|0x[0-9a-fA-F]+)\s*\)", "random_seed_call"),
            (r"\b(?:(?:new\s+)?(?:Random|srand))\s*\(\s*(-?\d+|0x[0-9a-fA-F]+)\s*\)", "prng_ctor"),
            (r"\b([0-9a-fA-F]{32,128})\b", "hex_hash"),
        ]
        
        found = []
        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in (extensions or {".py", ".js", ".ts", ".cs", ".c", ".cpp", ".h", ".rs", ".go", ".json", ".yaml", ".yml", ".md", ".txt"}):
                continue
            if any(part.startswith(".") and part not in {".gitignore", ".env"} for part in file_path.parts):
                continue
            try:
                text = file_path.read_text(errors="ignore")
                for pattern, kind in patterns:
                    import re
                    for match in re.finditer(pattern, text, re.IGNORECASE):
                        value = match.group(1)
                        value_sha256 = hashlib.sha256(value.encode()).hexdigest()
                        line = text[:match.start()].count("\n") + 1
                        found.append({
                            "address": str(file_path.relative_to(self.base_path)),
                            "line": line,
                            "kind": kind,
                            "value": value,
                            "value_sha256": value_sha256,
                            "file_sha256": hashlib.sha256(text.encode()).hexdigest()[:16],
                        })
            except Exception:
                continue
        
        self.seeds = [SeedRecord(**s) for s in found[:500]]
        return {"success": True, "seeds_found": len(found), "seeds_indexed": len(self.seeds)}

    def get_routing_stats(self) -> Dict[str, Any]:
        routed = sum(1 for s in self.seeds if s.routed)
        return {
            "total_seeds": len(self.seeds),
            "routed_seeds": routed,
            "routing_log_entries": len(self.routing_log),
            "active_connections": sum(1 for c in self.connections.values() if c.get("established")),
            "available_transports": self.get_available_transports(),
            "config": self.config,
        }

    def get_performance_report(self) -> Dict[str, Any]:
        recent_log = self.routing_log[-20:]
        success_routed = sum(1 for entry in recent_log if entry.get("routed"))
        return {
            "routing_stats": self.get_routing_stats(),
            "recent_routing_log": recent_log,
            "success_rate": success_routed / len(recent_log) if recent_log else 0.0,
            "connections": [
                {"id": k, "established": v.get("established"), "transport": v.get("transport"), "mac": v.get("mac")}
                for k, v in self.connections.items()
            ],
        }
