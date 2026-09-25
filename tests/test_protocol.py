from __future__ import annotations

import unittest
import uuid

from app.network.protocol import (
    CancelReason,
    ErrorCode,
    MessageType,
    ProtocolError,
    ProtocolSession,
    RejectReason,
    SessionState,
    TransferState,
    make_error,
    make_pair_request,
    make_pair_response,
    make_transfer_accept,
    make_transfer_cancel,
    make_transfer_complete,
    make_transfer_reject,
    make_transfer_request,
    make_transfer_start,
    message_to_bytes,
    message_to_dict,
    new_request_id,
    parse_bytes,
    parse_message,
    transition_transfer,
    validate_file_name,
)


HASH = "ab" * 32


class SerializationTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        original = make_transfer_request("photo.jpg", 128, HASH, "image/jpeg")
        restored = parse_bytes(message_to_bytes(original))
        self.assertEqual(restored.type, MessageType.TRANSFER_REQUEST)
        self.assertEqual(restored.request_id, original.request_id)
        self.assertEqual(restored.payload["file_name"], "photo.jpg")
        self.assertEqual(restored.payload["file_size"], 128)

    def test_hello_stays_flat(self) -> None:
        device_id = str(uuid.uuid4())
        message = parse_message(
            {
                "type": "HELLO",
                "protocol_version": 1,
                "device_id": device_id,
                "device_name": "DESKTOP-BOGDAN",
            }
        )
        self.assertEqual(message_to_dict(message)["device_name"], "DESKTOP-BOGDAN")
        self.assertNotIn("payload", message_to_dict(message))


class InvalidMessageTests(unittest.TestCase):
    def test_rejects_bad_inputs(self) -> None:
        with self.assertRaises(ProtocolError) as malformed:
            parse_bytes(b"{")
        self.assertEqual(malformed.exception.code, ErrorCode.MALFORMED_MESSAGE)
        with self.assertRaises(ProtocolError) as unknown:
            parse_message({"type": "CHAT", "protocol_version": 1, "payload": {}})
        self.assertEqual(unknown.exception.code, ErrorCode.INVALID_MESSAGE)
        with self.assertRaises(ProtocolError) as version:
            parse_message({"type": "PAIR_REQUEST", "protocol_version": 2, "payload": {}})
        self.assertEqual(version.exception.code, ErrorCode.UNSUPPORTED_PROTOCOL_VERSION)
        with self.assertRaises(ProtocolError) as missing:
            parse_message({"type": "PAIR_RESPONSE", "protocol_version": 1})
        self.assertEqual(missing.exception.code, ErrorCode.INVALID_PAYLOAD)
        with self.assertRaises(ProtocolError):
            parse_message(
                {
                    "type": "PAIR_RESPONSE",
                    "protocol_version": 1,
                    "request_id": str(uuid.uuid4()),
                    "payload": {"accepted": "yes"},
                }
            )
        with self.assertRaises(ProtocolError):
            make_transfer_request("photo.jpg", -1, HASH)
        with self.assertRaises(ProtocolError):
            make_transfer_request("photo.jpg", 999999999999999999, HASH)

    def test_filename_and_reason_are_constrained(self) -> None:
        for name in ("../secret.txt", "..\\secret.txt", r"C:\Windows\a.txt", "CON.txt", "bad:name.txt"):
            with self.assertRaises(ProtocolError):
                validate_file_name(name)
        with self.assertRaises(ProtocolError):
            parse_message(
                {
                    "type": "TRANSFER_REJECT",
                    "protocol_version": 1,
                    "request_id": str(uuid.uuid4()),
                    "payload": {"transfer_id": str(uuid.uuid4()), "reason": "FREE_TEXT"},
                }
            )
        self.assertEqual(validate_file_name("photo.jpg"), "photo.jpg")


class RequestIdTests(unittest.TestCase):
    def test_ids_are_unique(self) -> None:
        created = {new_request_id() for _ in range(1000)}
        self.assertEqual(len(created), 1000)
        message = make_pair_request(str(uuid.uuid4()), "LAPTOP")
        response = make_pair_response(message.request_id or "", True)
        self.assertEqual(response.request_id, message.request_id)
        self.assertTrue(response.payload["accepted"])


class StateMachineTests(unittest.TestCase):
    def test_valid_transfer_flow(self) -> None:
        session = ProtocolSession()
        session.apply(_hello())
        self.assertEqual(session.state, SessionState.READY)
        request = make_transfer_request("photo.jpg", 10, HASH)
        session.apply(request)
        transfer_id = request.payload["transfer_id"]
        session.apply(make_transfer_accept(request.request_id or "", transfer_id))
        session.apply(make_transfer_start(request.request_id or "", transfer_id))
        self.assertEqual(session.state, SessionState.TRANSFERRING)
        session.apply(make_transfer_complete(transfer_id, HASH))
        self.assertEqual(session.state, SessionState.READY)
        self.assertEqual(session.transfers[transfer_id], TransferState.COMPLETED)

    def test_complete_before_hello_is_rejected(self) -> None:
        session = ProtocolSession()
        with self.assertRaises(ProtocolError) as caught:
            session.apply(make_transfer_complete(str(uuid.uuid4()), HASH))
        self.assertEqual(caught.exception.code, ErrorCode.INVALID_STATE)

    def test_cancel_returns_to_ready(self) -> None:
        session = ProtocolSession()
        session.apply(_hello())
        request = make_transfer_request("photo.jpg", 10, HASH)
        session.apply(request)
        session.apply(make_transfer_accept(request.request_id or "", request.payload["transfer_id"]))
        session.apply(make_transfer_start(request.request_id or "", request.payload["transfer_id"]))
        session.apply(make_transfer_cancel(request.payload["transfer_id"], CancelReason.USER_CANCELLED))
        self.assertEqual(session.transfers[request.payload["transfer_id"]], TransferState.CANCELLED)
        self.assertEqual(session.state, SessionState.READY)


class TransferStateTests(unittest.TestCase):
    def test_allowed_transitions(self) -> None:
        self.assertEqual(transition_transfer(TransferState.REQUESTED, TransferState.ACCEPTED), TransferState.ACCEPTED)
        self.assertEqual(transition_transfer(TransferState.ACCEPTED, TransferState.STARTED), TransferState.STARTED)
        self.assertEqual(transition_transfer(TransferState.STARTED, TransferState.COMPLETED), TransferState.COMPLETED)
        self.assertEqual(transition_transfer(TransferState.STARTED, TransferState.CANCELLED), TransferState.CANCELLED)

    def test_completed_cannot_restart(self) -> None:
        with self.assertRaises(ProtocolError) as caught:
            transition_transfer(TransferState.COMPLETED, TransferState.STARTED)
        self.assertEqual(caught.exception.code, ErrorCode.INVALID_STATE)


class ErrorCodeTests(unittest.TestCase):
    def test_error_uses_controlled_code(self) -> None:
        message = make_error(ErrorCode.NOT_AUTHORIZED, "ignored by logic")
        self.assertEqual(message.payload["code"], ErrorCode.NOT_AUTHORIZED.value)
        with self.assertRaises(ProtocolError):
            parse_message(
                {
                    "type": "ERROR",
                    "protocol_version": 1,
                    "payload": {"code": "WHATEVER", "message": "x"},
                }
            )
        self.assertEqual(RejectReason.USER_REJECTED.value, "USER_REJECTED")


def _hello():
    return parse_message(
        {
            "type": "HELLO",
            "protocol_version": 1,
            "device_id": str(uuid.uuid4()),
            "device_name": "LAPTOP",
        }
    )
