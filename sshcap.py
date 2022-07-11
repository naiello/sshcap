import json
import logging
import socket
import sys
from datetime import datetime, timezone
from threading import Thread
from typing import Callable, Tuple, TypedDict

import click
from paramiko import ServerInterface
from paramiko.common import AUTH_FAILED
from paramiko.rsakey import RSAKey
from paramiko.transport import Transport

logger = logging.getLogger(__name__)

_DEFAULT_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4"


class CapturedCredential(TypedDict):
    timestamp: str
    src_ip: str
    src_port: int
    username: str
    password: str


CredentialCallback = Callable[[CapturedCredential], None]


class JSONLogger:
    def __init__(self, log_file: str) -> None:
        self._log_file = log_file

    def __call__(self, credential: CapturedCredential):
        line = json.dumps(credential)
        with open(self._log_file, "a") as f:
            f.write(f"{line}\n")


class CaptureServer(ServerInterface):
    def __init__(
        self, banner: str, src_ip: str, src_port, callback: CredentialCallback
    ) -> None:
        self._banner = banner
        self._src_ip = src_ip
        self._src_port = src_port
        self._callback = callback

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        logger.info(
            f"Captured credential for {username} from {self._src_ip}:{self._src_port}"
        )
        capture = CapturedCredential(
            username=username,
            password=password,
            src_ip=self._src_ip,
            src_port=self._src_port,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
        )
        self._callback(capture)
        return AUTH_FAILED

    def get_banner(self) -> Tuple[str, str]:
        return (self._banner, "en-US")


class ClientHandler(Thread):
    def __init__(
        self,
        server: ServerInterface,
        socket: socket.socket,
        addr: Tuple[str, int],
        banner: str,
        host_key: RSAKey,
    ) -> None:
        super().__init__()
        self._server = server
        self._socket = socket
        self._addr = addr
        self._banner = banner
        self._host_key = host_key

    def run(self) -> None:
        try:
            with Transport(self._socket) as t:
                t.add_server_key(self._host_key)
                t.local_version = self._banner
                t.start_server(server=self._server)
                t.accept(30)
        except Exception:
            pass
        finally:
            logger.info(f"Connection closed to {self._addr[0]}:{self._addr[1]}")


@click.command()
@click.option("--banner", default=_DEFAULT_BANNER, help="SSH banner to advertise")
@click.option("--port", default=22, help="Port to listen on")
@click.option(
    "--log-file", default="sshcap.log", help="File to log captured auth attempts"
)
@click.option("--server-key", default="sshcap.key", help="SSH server key file")
def main(banner: str, port: int, log_file: str, server_key: str):
    host_key = RSAKey(filename=server_key)
    callback = JSONLogger(log_file)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", port))
    except Exception:
        logger.exception("Failed to bind to socket")
        sys.exit(1)

    logger.info(f"Bound to port {port}")
    sock.listen(100)

    while True:
        try:
            client, addr = sock.accept()
        except Exception:
            logger.exception("Error while waiting for client")
            sys.exit(1)

        logger.info(f"Connection established to {addr}")

        server = CaptureServer(
            banner=banner,
            src_ip=addr[0],
            src_port=addr[1],
            callback=callback,
        )

        handler_thread = ClientHandler(
            server=server,
            socket=client,
            addr=addr,
            banner=banner,
            host_key=host_key,
        )

        handler_thread.start()


if __name__ == "__main__":
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    root.addHandler(handler)

    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
