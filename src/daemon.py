from argparse import Namespace
from os import path, remove, chmod, getpid
from socket import \
    socket, AF_UNIX, SOCK_STREAM, SOL_SOCKET, SCM_RIGHTS, CMSG_LEN
from struct import pack, unpack, calcsize
from threading import Thread
from subprocess import run

from src.operation import BaseOp
from src.helpers import Message
from src.token import Grants


class Daemon:
    SOCK_ADDRESS = "/run/fstokend/fstokend.sock"
    LENGTH_HEADER_SIZE = 4

    @staticmethod
    def _answer_request(conn: socket) -> None:
        operation = \
            Message \
            .from_bytes(conn.recv(Client.MAX_MESSAGE_SIZE)) \
            .payload

        op_result = operation.run_priviledged()
        fd = None
        mode = None
        if isinstance(op_result.payload, tuple):
            (file, mode) = op_result.payload
            if not op_result.err:
                fd = file.fileno()

        r_msg = bytes(Message(payload=mode if mode is not None else op_result.payload,
                              err=op_result.err,
                              hide_payload=op_result.hide_payload))
        length_header = pack("!I", len(r_msg))

        fd_data = []
        if fd:
            fd_data = [(SOL_SOCKET, SCM_RIGHTS, pack("i", fd))]

        conn.sendmsg([length_header + r_msg], fd_data)

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
    def _open_file(fd: int, mode: str) -> str:
        mode_args = ["-R"] if mode == Grants.READ.value else []
        cmd = ["vim", f"/proc/{getpid()}/fd/{fd}"]
        cmd.extend(mode_args)
        try:
            run(cmd)
        except Exception as err:
            return repr(err)

        return ""

    @staticmethod
    def _get_answer(length_header_size: int,
                    conn: socket) -> tuple[Message, int | None]:
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
            return \
                Message(payload=None,
                        err="Failed to get operation result from daemon"), None

        r_msg_length = unpack("!I", r_msg_length_bytes)[0]
        r_msg = Message.from_bytes(conn.recv(r_msg_length))

        fd = None
        for cmsg_level, cmsg_type, cmsg_data in anc_msg:
            if cmsg_level == SOL_SOCKET and cmsg_type == SCM_RIGHTS:
                fd = unpack("i", cmsg_data)[0]

        return r_msg, fd

    @classmethod
    def _call(cls, operation: BaseOp) -> Message:
        with socket(AF_UNIX, SOCK_STREAM) as conn:
            conn.connect(Daemon.SOCK_ADDRESS)
            conn.sendall(bytes(Message(operation, "")))

            (answer, fd) = cls._get_answer(Daemon.LENGTH_HEADER_SIZE, conn)

            err = answer.err
            if fd:
                err = cls._open_file(fd, answer.payload)

            return Message(
                payload=answer.get_exposable_payload(),
                err=err
            )

    @classmethod
    def call_daemon(cls, operation: BaseOp) -> Message:
        try:
            call_result = cls._call(operation)
        except ConnectionError:
            return Message(payload="", err="Failed to connect with fstoken daemon")

        return call_result


if __name__ == "__main__":
    Daemon.main()

