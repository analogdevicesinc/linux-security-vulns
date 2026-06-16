"""
Simple ASGI server that wraps the grondig binary.

On load, get grondig and post.db. Daily hot-reload post.db.
"""

import argparse
import asyncio
import atexit
import logging
import lzma
import os
import shutil
import signal
import tempfile
import threading
from pathlib import Path
from urllib.request import Request, urlopen

import schedule
import uvicorn

logger = logging.getLogger("pygrondig")

GRONDIG_URL = "https://github.com/analogdevicesinc/linux-security-vulns/releases/download/latest/grondig"
POSTDB_URL = "https://github.com/analogdevicesinc/linux-security-vulns/releases/download/latest/post.db.xz"


def _download(url, dest):
    logger.info("downloading %s -> %s", url, dest)
    req = Request(url)
    with urlopen(req) as resp, open(dest, "wb") as f:
        while chunk := resp.read(1 << 20):
            f.write(chunk)
    logger.info("downloaded %s (%d bytes)", dest, dest.stat().st_size)


def download_grondig(data_dir):
    grondig = data_dir / "grondig"
    if grondig.exists():
        logger.info("grondig binary already present, skipping download")
        return grondig
    _download(GRONDIG_URL, grondig)
    grondig.chmod(0o755)
    return grondig


def download_postdb(data_dir):
    xz_path = data_dir / "post.db.xz"
    db_path = data_dir / "post.db"
    tmp_path = data_dir / "post.db.tmp"

    _download(POSTDB_URL, xz_path)

    logger.info("decompressing %s", xz_path)
    with lzma.open(xz_path, "rb") as fin, open(tmp_path, "wb") as fout:
        while chunk := fin.read(1 << 20):
            fout.write(chunk)

    os.replace(tmp_path, db_path)
    xz_path.unlink(missing_ok=True)
    logger.info("post.db ready at %s", db_path)
    return db_path


class Scheduler:
    def __init__(self, data_dir):
        self._data_dir = data_dir
        self._stop = threading.Event()

        schedule.every().day.at("04:00").do(self._refresh_db)

    def _refresh_db(self):
        download_postdb(self._data_dir)

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        while not self._stop.is_set():
            schedule.run_pending()
            self._stop.wait(60)

    def stop(self):
        self._stop.set()


class Response:
    __slots__ = ("status_code", "headers", "body")

    def __init__(self, status_code, headers, body):
        self.status_code = status_code
        self.headers = headers
        self.body = body


async def send_response(send, response):
    body = (
        response.body
        if isinstance(response.body, bytes)
        else response.body.encode()
    )
    headers = [
        [k.encode(), v.encode()]
        for k, v in response.headers.items()
    ]
    headers.append([b"content-length", str(len(body)).encode()])
    await send({
        "type": "http.response.start",
        "status": response.status_code,
        "headers": headers,
    })
    await send({
        "type": "http.response.body",
        "body": body,
    })


async def read_body(receive):
    chunks = []
    while True:
        msg = await receive()
        chunks.append(msg.get("body", b""))
        if not msg.get("more_body", False):
            break
    return b"".join(chunks)


async def handle_grondig(env, body):
    if not body:
        return Response(
            400,
            {"content-type": "text/plain"},
            "Request body must be a grondig JSON query.\n",
        )
    proc = await asyncio.create_subprocess_exec(
        str(env["grondig"]), "--post-db", str(env["postdb"]),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate(input=body)

    if proc.returncode != 0:
        logger.error("grondig exited %d: %s", proc.returncode,
                     stderr.decode(errors="replace"))
        return Response(
            502,
            {"content-type": "text/plain"},
            f"grondig error (exit {proc.returncode}):\n"
            f"{stderr.decode(errors='replace')}",
        )

    return Response(
        200,
        {"content-type": "application/json"},
        stdout,
    )


ROUTES = {
    ("POST", "/grondig"): handle_grondig,
}


class App:
    def __init__(self, env):
        self.env = env

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return

        method = scope["method"]
        path = scope["path"]
        handler = ROUTES.get((method, path))

        if handler is None:
            await send_response(send, Response(
                404,
                {"content-type": "text/plain"},
                "Not found.\n",
            ))
            return

        body = await read_body(receive)
        response = await handler(self.env, body)
        await send_response(send, response)

def parse_args():
    parser = argparse.ArgumentParser(
        prog="pygrondig",
        description="ASGI server that spawns grondig instances to compute "
                    "Linux Kernel vulnerabilities.",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=8050,
        help="Port to listen on (default: 8050)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    data_dir = Path(tempfile.mkdtemp(prefix="pygrondig-"))
    atexit.register(shutil.rmtree, data_dir, ignore_errors=True)
    logger.info("data directory: %s", data_dir)

    grondig = download_grondig(data_dir)
    postdb = download_postdb(data_dir)

    env = {"grondig": grondig, "postdb": postdb, "data_dir": data_dir}

    sched = Scheduler(data_dir)
    sched.start()

    app = App(env)
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=args.port,
        log_level="debug" if args.verbose else "info",
    )
    server = uvicorn.Server(config)

    def signal_handler(sig, frame):
        sched.stop()
        server.should_exit = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    server.run()


if __name__ == "__main__":
    main()
