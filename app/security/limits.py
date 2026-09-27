from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 8 * 1024 * 1024 * 1024
    max_chunk_bytes: int = 256 * 1024
    max_metadata_bytes: int = 64 * 1024
    max_connections: int = 8
    max_concurrent_transfers: int = 2
    max_transfers_per_peer: int = 2
    timeout_seconds: float = 30.0


DEFAULT_LIMITS = Limits()

_TRANSFER_FLOOR_SECONDS = 600.0
_TRANSFER_CEILING_SECONDS = 4 * 60 * 60.0


def transfer_budget(size_bytes: int) -> float:
    size_mb = max(0, size_bytes) / (1024 * 1024)
    return min(_TRANSFER_CEILING_SECONDS, max(_TRANSFER_FLOOR_SECONDS, size_mb * 10.0))
