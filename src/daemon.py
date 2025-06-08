from typing import Any
from pickle import loads, dumps
from argparse import Namespace
from os import path, remove, chmod
from socket import socket, AF_UNIX, SOCK_STREAM
from concurrent.futures import ThreadPoolExecutor

from src.operation import BaseOp
from src.helpers import OpResult


class _SocketMessage:
    @staticmethod
    def from_bytes(as_bytes: bytes) -> "_SocketMessage":
        return loads(as_bytes)

    def __init__(self, payload: Any, err: str):
        self._payload = payload
        self._err = err

    def __bytes__(self) -> bytes:
        return dumps(self)

    @property
    def payload(self) -> Any:
        return self._payload

    @property
    def err(self) -> str:
        return self._err


class Daemon:
    SOCK_ADDRESS = "/run/fstokend/fstokend.sock"
    LENGTH_HEADER_SIZE = 4

    @staticmethod
    def _answer_request(conn: socket) -> None:
        operation = \
            _SocketMessage \
            .from_bytes(conn.recv(Client.MAX_MESSAGE_SIZE)) \
            .payload

        (err, result) = operation.run_priviledged()
        # implement client answer

        conn.close()

    @classmethod
    def main(cls) -> None:
        if path.exists(cls.SOCK_ADDRESS):
            remove(cls.SOCK_ADDRESS)

        with socket(AF_UNIX, SOCK_STREAM) as daemon_socket:
            daemon_socket.bind(cls.SOCK_ADDRESS)
            chmod(cls.SOCK_ADDRESS, 0o660)
            daemon_socket.listen()

            while True:
                (conn, _) = daemon_socket.accept()

                with ThreadPoolExecutor() as executor:
                    executor.submit(cls._answer_request, conn)


class Client:
    MAX_MESSAGE_SIZE = 1024

    @staticmethod
    def _partial_recv(size: int, conn: socket) -> bytes:
        data = b""

        while len(data) < size:
            bytes_received = conn.recv(size - len(data))
            if not bytes_received:
                return bytes()

            data += bytes_received

        return data

    @classmethod
    def _call(cls, operation: BaseOp) -> OpResult:
        with socket(AF_UNIX, SOCK_STREAM) as conn:
            conn.connect(Daemon.SOCK_ADDRESS)
            conn.sendall(bytes(_SocketMessage(operation, "")))

            answer_size = cls._partial_recv(Daemon.LENGTH_HEADER_SIZE, conn)
            daemon_answer = _SocketMessage.from_bytes(conn.recv(answer_size))

            return str(daemon_answer.payload), daemon_answer.err

    @classmethod
    def call_daemon(cls, operation: BaseOp) -> OpResult:
        try:
            (call_err, call_result) = cls._call(operation)
        except ConnectionError:
            return "Failed to connect with fstoken daemon", ""

        return call_err, call_result

if __name__ == "__main__":
    Daemon.main()

