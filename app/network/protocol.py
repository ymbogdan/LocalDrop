from __future__ import annotations

import json
import struct
import uuid
from dataclasses import dataclass, field
from enum import Enum

from app.device.identity import MAX_NAME_LENGTH, normalize_device_name
from app.network.constants import PROTOCOL_VERSION

MAX_CONTROL_MESSAGE_SIZE = 64 * 1024
MAX_DEVICE_NAME_LENGTH = MAX_NAME_LENGTH
MAX_FILE_NAME_LENGTH = 255
MAX_ERROR_MESSAGE_LENGTH = 256
MAX_MIME_TYPE_LENGTH = 127
MAX_FILE_SIZE = 8 * 1024 * 1024 * 1024

_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_INVALID_NAME_CHARS = set('<>:"|?*')


class MessageType(str, Enum):
    HELLO = "HELLO"
    PAIR_REQUEST = "PAIR_REQUEST"
    PAIR_RESPONSE = "PAIR_RESPONSE"
    TRANSFER_REQUEST = "TRANSFER_REQUEST"
    TRANSFER_ACCEPT = "TRANSFER_ACCEPT"
    TRANSFER_REJECT = "TRANSFER_REJECT"
    TRANSFER_START = "TRANSFER_START"
    TRANSFER_DATA = "TRANSFER_DATA"
    TRANSFER_COMPLETE = "TRANSFER_COMPLETE"
    TRANSFER_CANCEL = "TRANSFER_CANCEL"
    ERROR = "ERROR"


class ErrorCode(str, Enum):
    INVALID_MESSAGE = "INVALID_MESSAGE"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"
    MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"
    INVALID_REQUEST = "INVALID_REQUEST"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    UNKNOWN_TRANSFER = "UNKNOWN_TRANSFER"
    INVALID_STATE = "INVALID_STATE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    INVALID_MESSAGE_SIZE = "INVALID_MESSAGE_SIZE"
    INVALID_PROTOCOL_VERSION = "INVALID_PROTOCOL_VERSION"
    INVALID_DEVICE_ID = "INVALID_DEVICE_ID"
    MALFORMED_MESSAGE = "MALFORMED_MESSAGE"


class RejectReason(str, Enum):
    USER_REJECTED = "USER_REJECTED"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    INVALID_REQUEST = "INVALID_REQUEST"
    INSUFFICIENT_STORAGE = "INSUFFICIENT_STORAGE"
    UNSUPPORTED_FILE = "UNSUPPORTED_FILE"


class CancelReason(str, Enum):
    USER_CANCELLED = "USER_CANCELLED"
    CONNECTION_LOST = "CONNECTION_LOST"
    TIMEOUT = "TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class SessionState(str, Enum):
    CONNECTED = "CONNECTED"
    READY = "READY"
    WAITING_FOR_RESPONSE = "WAITING_FOR_RESPONSE"
    TRANSFERRING = "TRANSFERRING"


class TransferState(str, Enum):
    REQUESTED = "REQUESTED"
    ACCEPTED = "ACCEPTED"
    STARTED = "STARTED"
    TRANSFERRING = "TRANSFERRING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


_TRANSFER_TRANSITIONS: dict[TransferState, set[TransferState]] = {
    TransferState.REQUESTED: {
        TransferState.ACCEPTED,
        TransferState.CANCELLED,
        TransferState.FAILED,
        TransferState.REJECTED,
    },
    TransferState.ACCEPTED: {TransferState.STARTED, TransferState.CANCELLED, TransferState.FAILED},
    TransferState.STARTED: {
        TransferState.TRANSFERRING,
        TransferState.COMPLETED,
        TransferState.CANCELLED,
        TransferState.FAILED,
    },
    TransferState.TRANSFERRING: {TransferState.COMPLETED, TransferState.CANCELLED, TransferState.FAILED},
    TransferState.COMPLETED: set(),
    TransferState.CANCELLED: set(),
    TransferState.REJECTED: set(),
    TransferState.FAILED: set(),
}


@dataclass(frozen=True)
class Timeouts:
    connect: float = 5.0
    handshake: float = 5.0
    read: float = 10.0
    write: float = 10.0
    idle: float = 60.0


@dataclass(frozen=True)
class Message:
    type: MessageType
    protocol_version: int
    request_id: str | None = None
    transfer_id: str | None = None
    payload: dict = field(default_factory=dict)


class ProtocolError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def new_request_id() -> str:
    return str(uuid.uuid4())


def new_transfer_id() -> str:
    return str(uuid.uuid4())


def encode_message(payload: dict, limit: int = MAX_CONTROL_MESSAGE_SIZE) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(body) > limit:
        raise ProtocolError(ErrorCode.INVALID_MESSAGE_SIZE, "Control message is too large")
    return struct.pack(">I", len(body)) + body


def decode_message(body: bytes) -> dict:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(ErrorCode.MALFORMED_MESSAGE, "Control message is malformed") from exc
    if not isinstance(payload, dict):
        raise ProtocolError(ErrorCode.MALFORMED_MESSAGE, "Control message is malformed")
    return payload


def read_size(header: bytes, limit: int = MAX_CONTROL_MESSAGE_SIZE) -> int:
    if len(header) != 4:
        raise ProtocolError(ErrorCode.MALFORMED_MESSAGE, "Control message is malformed")
    size = struct.unpack(">I", header)[0]
    if size <= 0 or size > limit:
        raise ProtocolError(ErrorCode.INVALID_MESSAGE_SIZE, "Control message is too large")
    return size


def hello_payload(device_id: str, device_name: str) -> dict:
    return {
        "type": MessageType.HELLO.value,
        "protocol_version": PROTOCOL_VERSION,
        "device_id": device_id,
        "device_name": device_name,
    }


def error_payload(code: str, message: str = "", request_id: str | None = None) -> dict:
    parsed = _enum_value(ErrorCode, code, ErrorCode.INVALID_MESSAGE)
    payload: dict = {
        "type": MessageType.ERROR.value,
        "protocol_version": PROTOCOL_VERSION,
        "payload": {"code": parsed, "message": _limited_text(message, MAX_ERROR_MESSAGE_LENGTH)},
    }
    if request_id is not None:
        payload["request_id"] = request_id
    return payload


def peer_error_code(payload: dict) -> str:
    nested = payload.get("payload")
    if isinstance(nested, dict) and isinstance(nested.get("code"), str):
        return nested["code"]
    code = payload.get("code")
    if isinstance(code, str):
        return code
    return ErrorCode.INVALID_MESSAGE.value


def validate_hello(payload: dict) -> tuple[str, str]:
    if payload.get("type") != MessageType.HELLO.value:
        raise ProtocolError(ErrorCode.MALFORMED_MESSAGE, "Expected HELLO")
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        raise ProtocolError(ErrorCode.INVALID_PROTOCOL_VERSION, "Unsupported protocol version")
    message = parse_message(payload)
    return str(message.payload["device_id"]), str(message.payload["device_name"])


def parse_bytes(body: bytes) -> Message:
    if not body.startswith(b"{"):
        size = read_size(body[:4])
        body = body[4 : 4 + size]
    return parse_message(decode_message(body))


def parse_message(data: dict) -> Message:
    if not isinstance(data, dict):
        raise ProtocolError(ErrorCode.INVALID_MESSAGE, "Message is not an object")
    message_type = _message_type(data.get("type"))
    version = data.get("protocol_version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise ProtocolError(ErrorCode.UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version")
    if version != PROTOCOL_VERSION:
        raise ProtocolError(ErrorCode.UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version")
    request_id = _optional_id(data.get("request_id"), "request_id")
    transfer_id = _optional_id(data.get("transfer_id"), "transfer_id")
    if message_type == MessageType.HELLO:
        return _parse_hello(data, request_id)
    raw_payload = data.get("payload")
    if not isinstance(raw_payload, dict):
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Payload is missing")
    payload = _parse_payload(message_type, raw_payload)
    if transfer_id is None:
        transfer_id = payload.get("transfer_id")
    return Message(message_type, version, request_id, transfer_id if isinstance(transfer_id, str) else None, payload)


def message_to_dict(message: Message) -> dict:
    if message.type == MessageType.HELLO:
        body = hello_payload(str(message.payload["device_id"]), str(message.payload["device_name"]))
        certificate = message.payload.get("successor_certificate")
        proof = message.payload.get("successor_proof")
        if isinstance(certificate, str) and isinstance(proof, str) and certificate and proof:
            body["successor_certificate"] = certificate
            body["successor_proof"] = proof
        return body
    body: dict = {
        "type": message.type.value,
        "protocol_version": message.protocol_version,
        "payload": {key: value for key, value in message.payload.items() if key != "data"},
    }
    if message.request_id is not None:
        body["request_id"] = message.request_id
    if message.transfer_id is not None and message.type in {
        MessageType.TRANSFER_COMPLETE,
        MessageType.TRANSFER_CANCEL,
        MessageType.TRANSFER_DATA,
    }:
        body["transfer_id"] = message.transfer_id
    return body


def message_to_bytes(message: Message) -> bytes:
    return encode_message(message_to_dict(message))


def make_pair_request(device_id: str, device_name: str, request_id: str | None = None) -> Message:
    return parse_message(
        {
            "type": MessageType.PAIR_REQUEST.value,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id or new_request_id(),
            "payload": {"device_id": device_id, "device_name": device_name},
        }
    )


def make_pair_response(request_id: str, accepted: bool) -> Message:
    return parse_message(
        {
            "type": MessageType.PAIR_RESPONSE.value,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "payload": {"accepted": accepted},
        }
    )


def make_transfer_request(
    file_name: str,
    file_size: int,
    file_hash: str,
    mime_type: str = "",
    request_id: str | None = None,
    transfer_id: str | None = None,
) -> Message:
    return parse_message(
        {
            "type": MessageType.TRANSFER_REQUEST.value,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id or new_request_id(),
            "payload": {
                "transfer_id": transfer_id or new_transfer_id(),
                "file_name": file_name,
                "file_size": file_size,
                "file_hash": file_hash,
                "mime_type": mime_type,
            },
        }
    )


def make_transfer_accept(request_id: str, transfer_id: str) -> Message:
    return _simple_transfer(MessageType.TRANSFER_ACCEPT, request_id, transfer_id)


def make_transfer_reject(request_id: str, transfer_id: str, reason: RejectReason) -> Message:
    return parse_message(
        {
            "type": MessageType.TRANSFER_REJECT.value,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "payload": {"transfer_id": transfer_id, "reason": reason.value},
        }
    )


def make_transfer_start(request_id: str, transfer_id: str) -> Message:
    return _simple_transfer(MessageType.TRANSFER_START, request_id, transfer_id)


def make_transfer_complete(transfer_id: str, sha256: str) -> Message:
    return parse_message(
        {
            "type": MessageType.TRANSFER_COMPLETE.value,
            "protocol_version": PROTOCOL_VERSION,
            "transfer_id": transfer_id,
            "payload": {"sha256": sha256},
        }
    )


def make_transfer_cancel(transfer_id: str, reason: CancelReason) -> Message:
    return parse_message(
        {
            "type": MessageType.TRANSFER_CANCEL.value,
            "protocol_version": PROTOCOL_VERSION,
            "transfer_id": transfer_id,
            "payload": {"reason": reason.value},
        }
    )


def make_error(code: ErrorCode, message: str = "", request_id: str | None = None) -> Message:
    return parse_message(error_payload(code.value, message, request_id))


def transition_transfer(current: TransferState, new_state: TransferState) -> TransferState:
    if new_state not in _TRANSFER_TRANSITIONS[current]:
        raise ProtocolError(ErrorCode.INVALID_STATE, "Invalid transfer transition")
    return new_state


class ProtocolSession:
    def __init__(self) -> None:
        self.state = SessionState.CONNECTED
        self.transfers: dict[str, TransferState] = {}

    def apply(self, message: Message) -> None:
        if message.type == MessageType.HELLO:
            self._expect(SessionState.CONNECTED)
            self.state = SessionState.READY
            return
        if message.type in {MessageType.PAIR_REQUEST, MessageType.PAIR_RESPONSE, MessageType.ERROR}:
            self._expect(SessionState.READY)
            return
        if message.type == MessageType.TRANSFER_REQUEST:
            self._expect(SessionState.READY)
            transfer_id = _required_transfer(message)
            self.transfers[transfer_id] = TransferState.REQUESTED
            self.state = SessionState.WAITING_FOR_RESPONSE
            return
        if message.type == MessageType.TRANSFER_ACCEPT:
            self._expect(SessionState.WAITING_FOR_RESPONSE)
            self._move(_required_transfer(message), TransferState.ACCEPTED)
            return
        if message.type == MessageType.TRANSFER_REJECT:
            self._expect(SessionState.WAITING_FOR_RESPONSE)
            self._move(_required_transfer(message), TransferState.FAILED)
            self.state = SessionState.READY
            return
        if message.type == MessageType.TRANSFER_START:
            self._expect(SessionState.WAITING_FOR_RESPONSE)
            self._move(_required_transfer(message), TransferState.STARTED)
            self.state = SessionState.TRANSFERRING
            return
        if message.type == MessageType.TRANSFER_COMPLETE:
            self._expect(SessionState.TRANSFERRING)
            self._move(_required_transfer(message), TransferState.COMPLETED)
            self.state = SessionState.READY
            return
        if message.type == MessageType.TRANSFER_CANCEL:
            if self.state not in {SessionState.WAITING_FOR_RESPONSE, SessionState.TRANSFERRING}:
                raise ProtocolError(ErrorCode.INVALID_STATE, "Invalid session state")
            self._move(_required_transfer(message), TransferState.CANCELLED)
            self.state = SessionState.READY
            return
        raise ProtocolError(ErrorCode.INVALID_STATE, "Invalid session state")

    def _expect(self, state: SessionState) -> None:
        if self.state != state:
            raise ProtocolError(ErrorCode.INVALID_STATE, "Invalid session state")

    def _move(self, transfer_id: str, new_state: TransferState) -> None:
        current = self.transfers.get(transfer_id)
        if current is None:
            raise ProtocolError(ErrorCode.UNKNOWN_TRANSFER, "Unknown transfer")
        self.transfers[transfer_id] = transition_transfer(current, new_state)


def validate_file_name(file_name: object) -> str:
    if not isinstance(file_name, str) or not file_name or file_name != file_name.strip():
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid file name")
    if len(file_name) > MAX_FILE_NAME_LENGTH:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid file name")
    if any(character in file_name for character in _INVALID_NAME_CHARS):
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid file name")
    if "/" in file_name or "\\" in file_name or ":" in file_name or "\x00" in file_name:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid file name")
    if file_name in {".", ".."} or ".." in file_name:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid file name")
    if file_name.endswith((" ", ".")):
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid file name")
    stem = file_name.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid file name")
    return file_name


def _parse_hello(data: dict, request_id: str | None) -> Message:
    device_id = _device_id(data.get("device_id"))
    device_name = _device_name(data.get("device_name"))
    payload = {"device_id": device_id, "device_name": device_name}
    certificate = data.get("successor_certificate")
    proof = data.get("successor_proof")
    if (
        isinstance(certificate, str)
        and isinstance(proof, str)
        and certificate
        and proof
        and len(certificate) <= 20_000
        and len(proof) <= 2_000
    ):
        payload["successor_certificate"] = certificate
        payload["successor_proof"] = proof
    return Message(
        MessageType.HELLO,
        PROTOCOL_VERSION,
        request_id,
        None,
        payload,
    )


def _parse_payload(message_type: MessageType, payload: dict) -> dict:
    if message_type == MessageType.PAIR_REQUEST:
        return {
            "device_id": _device_id(payload.get("device_id")),
            "device_name": _device_name(payload.get("device_name")),
        }
    if message_type == MessageType.PAIR_RESPONSE:
        accepted = payload.get("accepted")
        if not isinstance(accepted, bool):
            raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid pairing response")
        return {"accepted": accepted}
    if message_type == MessageType.TRANSFER_REQUEST:
        return {
            "transfer_id": _required_id(payload.get("transfer_id"), "transfer_id"),
            "file_name": validate_file_name(payload.get("file_name")),
            "file_size": _file_size(payload.get("file_size")),
            "file_hash": _sha256(payload.get("file_hash")),
            "mime_type": _mime(payload.get("mime_type", "")),
        }
    if message_type in {MessageType.TRANSFER_ACCEPT, MessageType.TRANSFER_START}:
        return {"transfer_id": _required_id(payload.get("transfer_id"), "transfer_id")}
    if message_type == MessageType.TRANSFER_REJECT:
        return {
            "transfer_id": _required_id(payload.get("transfer_id"), "transfer_id"),
            "reason": _enum_value(RejectReason, payload.get("reason"), None),
        }
    if message_type == MessageType.TRANSFER_COMPLETE:
        return {"sha256": _sha256(payload.get("sha256"))}
    if message_type == MessageType.TRANSFER_DATA:
        data = _chunk_bytes(payload.get("data_b64"))
        return {
            "offset": _offset(payload.get("offset")),
            "data_b64": payload.get("data_b64") if isinstance(payload.get("data_b64"), str) else "",
            "data": data,
        }
    if message_type == MessageType.TRANSFER_CANCEL:
        return {"reason": _enum_value(CancelReason, payload.get("reason"), None)}
    if message_type == MessageType.ERROR:
        return {
            "code": _enum_value(ErrorCode, payload.get("code"), None),
            "message": _limited_text(payload.get("message", ""), MAX_ERROR_MESSAGE_LENGTH),
        }
    raise ProtocolError(ErrorCode.INVALID_MESSAGE, "Unknown message type")


def _simple_transfer(message_type: MessageType, request_id: str, transfer_id: str) -> Message:
    return parse_message(
        {
            "type": message_type.value,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "payload": {"transfer_id": transfer_id},
        }
    )


def _message_type(value: object) -> MessageType:
    if not isinstance(value, str):
        raise ProtocolError(ErrorCode.INVALID_MESSAGE, "Unknown message type")
    try:
        return MessageType(value)
    except ValueError as exc:
        raise ProtocolError(ErrorCode.INVALID_MESSAGE, "Unknown message type") from exc


def _device_id(value: object) -> str:
    if not isinstance(value, str):
        raise ProtocolError(ErrorCode.INVALID_DEVICE_ID, "Invalid device id")
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise ProtocolError(ErrorCode.INVALID_DEVICE_ID, "Invalid device id") from exc


def _device_name(value: object) -> str:
    if not isinstance(value, str):
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid device name")
    try:
        return normalize_device_name(value)
    except ValueError as exc:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid device name") from exc


def _optional_id(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _required_id(value, field_name)


def _required_id(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, f"Invalid {field_name}")
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, f"Invalid {field_name}") from exc


def _required_transfer(message: Message) -> str:
    transfer_id = message.transfer_id or message.payload.get("transfer_id")
    if not isinstance(transfer_id, str):
        raise ProtocolError(ErrorCode.UNKNOWN_TRANSFER, "Unknown transfer")
    return transfer_id


def _offset(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid offset")
    return value


def _chunk_bytes(value: object) -> bytes:
    import base64

    if not isinstance(value, str):
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid chunk")
    try:
        data = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid chunk") from exc
    if len(data) > 32 * 1024:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid chunk")
    return data


def _file_size(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > MAX_FILE_SIZE:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid file size")
    return value


def _sha256(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid hash")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid hash") from exc
    return value.lower()


def _mime(value: object) -> str:
    if not isinstance(value, str) or len(value) > MAX_MIME_TYPE_LENGTH:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid mime type")
    if any(ord(character) < 32 for character in value):
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid mime type")
    return value


def _limited_text(value: object, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid text")
    return value


def _enum_value(enum_type: type[Enum], value: object, default: Enum | None) -> str:
    if not isinstance(value, str):
        if default is None:
            raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid code")
        return str(default.value)
    try:
        return str(enum_type(value).value)
    except ValueError as exc:
        if default is not None and enum_type is ErrorCode:
            raise ProtocolError(ErrorCode.INVALID_MESSAGE, "Invalid error code") from exc
        raise ProtocolError(ErrorCode.INVALID_PAYLOAD, "Invalid code") from exc
