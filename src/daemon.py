from argparse import Namespace
from traceback import format_exception
from functools import reduce
from os import path, remove, chmod
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from threading import Thread

from operation import BaseOp, Invoke
from helpers import Message


class _SocketMessageBroker:
    _LENGTH_HEADER_SIZE = 4
    _LENGTH_HEADER_FORMAT = "!I"

    @classmethod
    def get_message(cls, conn: socket) -> Message:
        msg_length_bytes = b""
        failed_read = False
        while len(msg_length_bytes) < cls._LENGTH_HEADER_SIZE:
            expected_read_size = cls._LENGTH_HEADER_SIZE - len(msg_length_bytes)
            length_bytes = conn.recv(expected_read_size)

            if not length_bytes:
                failed_read = True

            msg_length_bytes += length_bytes

        if failed_read:
            return Message(payload=None, err="Failed to read message")

        msg_length = unpack(cls._LENGTH_HEADER_FORMAT, msg_length_bytes)[0]
        return Message.from_bytes(conn.recv(msg_length))

    @classmethod
    def send_message(cls, conn: socket, message: Message) -> None:
        msg = bytes()
        try:
            msg = bytes(message)
        except Exception as err:
            msg = bytes(Message(payload=None,
                                err=f"Failed to get message bytes: {repr(err)}"))

        msg_length = pack(cls._LENGTH_HEADER_FORMAT, len(msg))
        conn.sendall(msg_length + msg)


class Daemon:
    SOCK_ADDRESS = "/run/fstokend/fstokend.sock"
    LENGTH_HEADER_SIZE = 4

    @staticmethod
    def _get_exception_str(err: Exception) -> str:
        return reduce(lambda exc_str, curr_str: exc_str + curr_str,
                      format_exception(err))

    @staticmethod
    def _answer_request(cls: "Daemon", conn: socket) -> None:
        try:
            client_msg = _SocketMessageBroker.get_message(conn)
            operation: BaseOp = client_msg.payload

            op_result = operation.run_priviledged()
            _SocketMessageBroker.send_message(conn, op_result)

            if isinstance(operation, Invoke) and not op_result.err:
                invocation_answer_msg = _SocketMessageBroker.get_message(conn)
                if not invocation_answer_msg.err:
                    operation.update_file(invocation_answer_msg)
        except Exception as err:
            exc_string = cls._get_exception_str(err)
            err_msg = Message(payload=None,
                              err=f"Unexpected runtime error:\n{exc_string}")
            _SocketMessageBroker.send_message(conn, err_msg)

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


                    t = Thread(target=cls._answer_request, args=(cls, conn,))
                    t.start()
                    conn_threads.append(t)
            except KeyboardInterrupt:
                for t in conn_threads:
                    t.join()


class Client:
    @classmethod
    def _call(cls, operation: BaseOp) -> Message:
        with socket(AF_UNIX, SOCK_STREAM) as conn:
            conn.connect(Daemon.SOCK_ADDRESS)
            _SocketMessageBroker.send_message(conn, Message(operation, ""))

            daemon_msg = _SocketMessageBroker.get_message(conn)

            op_result = daemon_msg
            if isinstance(operation, Invoke) and not op_result.err:
                prompt_result = \
                    operation.prompt_user_with_file_editor(daemon_msg)

                _SocketMessageBroker.send_message(conn, prompt_result)

                op_result = prompt_result

            return Message(payload=op_result.get_exposable_payload(),
                           err=op_result.err)

    @classmethod
    def call_daemon(cls, operation: BaseOp) -> Message:
        try:
            call_result = cls._call(operation)
        except ConnectionError:
            return Message(payload="", err="Failed to connect with fstoken daemon")

        return call_result


if __name__ == "__main__":
    Daemon.main()

