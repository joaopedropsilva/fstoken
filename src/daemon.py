from os import path, remove
from socket import socket, AF_UNIX, SOCK_STREAM
from threading import Thread
from time import sleep


class Daemon:
    SOCK_ADDRESS = "/tmp/fstokend.sock"

    @staticmethod
    def get_requested_fp(conn: socket) -> None:
        data = conn.recv(1024)
        print(f"data: {data}")
        sleep(10)
        conn.close()

    @classmethod
    def main(cls):
        if path.exists(cls.SOCK_ADDRESS):
            remove(cls.SOCK_ADDRESS)

        answer_threads = []
        with socket(AF_UNIX, SOCK_STREAM) as s:
            s.bind(cls.SOCK_ADDRESS)
            print("Start listening")
            s.listen()

            try:
                while True:
                    (conn, _) = s.accept()
                    print("accepted")

                    t = Thread(target=cls.get_requested_fp,
                               args=(conn,))
                    t.start()
                    answer_threads.append(t)
            except KeyboardInterrupt:
                print("waiting for threads")
                for t in answer_threads:
                    t.join()


class Client:
    @staticmethod
    def call_daemon():
        with socket(AF_UNIX, SOCK_STREAM) as s:
            s.connect(Daemon.SOCK_ADDRESS)

            print("sending to...")
            s.sendall(b"Hello from client")


if __name__ == "__main__":
    Daemon.main()

