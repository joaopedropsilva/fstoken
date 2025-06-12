from argparse import Namespace
from os import path, remove, chmod
from socket import \
    socket, AF_UNIX, SOCK_STREAM, SOL_SOCKET, SCM_RIGHTS, CMSG_LEN
from struct import pack, unpack, calcsize
from threading import Thread
from io import TextIOWrapper

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

        file = None
        mode = None
        if isinstance(result, tuple):
            (file, mode) = result

        answer = bytes(SocketMessage(result if mode is None else mode, err))
        length_header = pack("!I", len(answer))

        fd_data = []
        if file:
            fd_data = [(SOL_SOCKET, SCM_RIGHTS, pack("i", file.fileno()))]

        conn.sendmsg([length_header + answer], fd_data)

        conn.close()

    @classmethod
    def main(cls) -> None:
        if path.exists(cls.SOCK_ADDRESS):
            remove(cls.SOCK_ADDRESS)

        with socket(AF_UNIX, SOCK_STREAM) as daemon_socket:
            daemon_socket.bind(cls.SOCK_ADDRESS)
            chmod(cls.SOCK_ADDRESS, 0o660)
            daemon_socket.listen()

            conn_threads = []
            try:
                while True:
                    (conn, _) = daemon_socket.accept()


                    t = Thread(target=cls._answer_request, args=(conn,))
                    t.start()
                    conn_threads.append(t)
            except KeyboardInterrupt:
                for t in conn_threads:
                    t.join()


class Client:
    MAX_MESSAGE_SIZE = 1024

    @staticmethod
    def _get_answer(length_header_size: int,
                    conn: socket) -> tuple[SocketMessage, TextIOWrapper | None]:
        r_msg_length_bytes = b""
        a_size_expected = CMSG_LEN(calcsize("i"))
        failed_read = False
        while len(r_msg_length_bytes) < length_header_size:
            r_size_expected = length_header_size - len(r_msg_length_bytes)
            (raw_r_msg_length, anc_msg, _, _) = conn.recvmsg(r_size_expected,
                                                             a_size_expected)
            if not raw_r_msg_length:
                failed_read = True

            r_msg_length_bytes += raw_r_msg_length

        if failed_read:
            return "Failed to get operation result from daemon", None

        r_msg_length = unpack("!I", r_msg_length_bytes)[0]
        regular_msg = SocketMessage.from_bytes(conn.recv(r_msg_length))

        fd = None
        for cmsg_level, cmsg_type, cmsg_data in anc_msg:
            if cmsg_level == SOL_SOCKET and cmsg_type == SCM_RIGHTS:
                fd = unpack("i", cmsg_data)[0]
        file = None
        if fd:
            mode = regular_msg.payload
            file = open(fd, mode)
            regular_msg.payload = ""

        return regular_msg, file

    @classmethod
    def _call(cls, operation: BaseOp) -> OpResult:
        with socket(AF_UNIX, SOCK_STREAM) as conn:
            conn.connect(Daemon.SOCK_ADDRESS)
            conn.sendall(bytes(SocketMessage(operation, "")))

            (answer, file) = cls._get_answer(Daemon.LENGTH_HEADER_SIZE, conn)

            return answer.err, str(answer.payload)

    @classmethod
    def call_daemon(cls, operation: BaseOp) -> OpResult:
        try:
            (call_err, call_result) = cls._call(operation)
        except ConnectionError:
            return "Failed to connect with fstoken daemon", ""

        return call_err, call_result

if __name__ == "__main__":
    Daemon.main()

