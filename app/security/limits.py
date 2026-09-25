from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 8 * 1024 * 1024 * 1024
    max_chunk_bytes: int = 256 * 1024
    max_metadata_bytes: int = 64 * 1024
    max_connections: int = 8
    max_concurrent_transfers: int = 2
    timeout_seconds: float = 30.0


DEFAULT_LIMITS = Limits()
