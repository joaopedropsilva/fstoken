from typing import Any
from pickle import loads, dumps
from argparse import Namespace
from os import path, remove, chmod
from socket import socket, AF_UNIX, SOCK_STREAM
from concurrent.futures import ThreadPoolExecutor

from src.helpers import OpResult, log, log_err


class Daemon:
    SOCK_ADDRESS = "/run/fstokend/fstokend.sock"
    LENGTH_HEADER_SIZE = 4

    @staticmethod
    def _answer_request(conn: socket) -> None:
        data = conn.recv(Client.MAX_MESSAGE_SIZE)
        op_args_repr = loads(data)

        (operation, args_repr) = op_args_repr.split(Client.OP_ARGS_SEP)
        conn.sendall(dumps(res))
        conn.close()

    @classmethod
    def main(cls) -> None:
        if path.exists(cls.SOCK_ADDRESS):
            remove(cls.SOCK_ADDRESS)

        with socket(AF_UNIX, SOCK_STREAM) as s:
            s.bind(cls.SOCK_ADDRESS)
            chmod(cls.SOCK_ADDRESS, 0o660)
            s.listen()

            while True:
                print("accepting")
                (conn, _) = daemon_socket.accept()

                with ThreadPoolExecutor() as executor:
                    executor.submit(cls._answer_request, conn)


class Client:
    OP_ARGS_SEP = "__"
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

    @staticmethod
    def _interpret_daemon_answer(as_bytes) -> OpResult:

    @classmethod
    def _get_op_args_repr(cls, operation: str, args: Namespace) -> bytes:
        args_repr = ""
        all_args = \
            repr(args) \
            .replace("Namespace(", "") \
            .replace(")", "") \
            .split(", ")
        for index, arg_str in enumerate(all_args):
            if index != len(all_args):
                args_repr += f"{arg_str};"
                continue
            args_repr += f"{arg_str}"

        op_args_repr = f"{operation}{cls.OP_ARGS_SEP}{args_repr}"

        return dumps(op_args_repr)

    @classmethod
    def call_daemon(cls, operation: str, args: Namespace) -> None:
        with socket(AF_UNIX, SOCK_STREAM) as conn:
            conn.connect(Daemon.SOCK_ADDRESS)

            conn.sendall(cls._get_op_args_repr(operation, args))

            answer_size = cls._partial_recv(Daemon.LENGTH_HEADER_SIZE, conn)
            daemon_answer = conn.recv(answer_size)
            (result, errors) = cls._interpret_daemon_answer(daemon_answer)

            log(result, verbose=True)
            log_err(errors)


if __name__ == "__main__":
    Daemon.main()

