from argparse import Namespace
from os import path, remove, chmod
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from concurrent.futures import ThreadPoolExecutor

from src.operation import BaseOp
from src.helpers import OpResult, SocketMessage


class Daemon:
    SOCK_ADDRESS = "/run/fstokend/fstokend.sock"
    LENGTH_HEADER_SIZE = 4

    @staticmethod
    def _answer_request(conn: socket) -> None:
        operation = \
            SocketMessage \
            .from_bytes(conn.recv(Client.MAX_MESSAGE_SIZE)) \
            .payload

        (err, result) = operation.run_priviledged()

        answer = bytes(SocketMessage(result, err))
        length_header = pack("!I", len(answer))
        conn.sendall(length_header + answer)

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
    def _get_answer_size(length_header_size: int, conn: socket) -> int:
        data = b""

        could_read = True
        while len(data) < length_header_size:
            bytes_received = conn.recv(length_header_size - len(data))
            if not bytes_received:
                could_read = False

            data += bytes_received

        if not could_read:
            return 0

        size = unpack("!I", data)[0]

        return int(size)

    @classmethod
    def _call(cls, operation: BaseOp) -> OpResult:
        with socket(AF_UNIX, SOCK_STREAM) as conn:
            conn.connect(Daemon.SOCK_ADDRESS)
            conn.sendall(bytes(SocketMessage(operation, "")))

            answer_size = cls._get_answer_size(Daemon.LENGTH_HEADER_SIZE, conn)
            if answer_size == 0:
                return "Failed to get operation result from daemon", ""
            daemon_answer = SocketMessage.from_bytes(conn.recv(answer_size))

            return daemon_answer.err, str(daemon_answer.payload)

    @classmethod
    def call_daemon(cls, operation: BaseOp) -> OpResult:
        try:
            (call_err, call_result) = cls._call(operation)
        except ConnectionError:
            return "Failed to connect with fstoken daemon", ""

        return call_err, call_result

if __name__ == "__main__":
    Daemon.main()

