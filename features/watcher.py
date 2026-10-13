"""
features/watcher.py — watches the capture directory for new PCAPs and turns
each one into an IPsecFeatureRow published to Kafka 'raw-features'.

    python -m features.watcher                        # watch $CAPTURES_DIR (default capture/pcaps)
    python -m features.watcher --replay capture/pcaps # process existing PCAPs, publish, exit
    python -m features.watcher --replay x.pcap --no-kafka   # extract only (writes parquet)

For each PCAP: features/ike_parser.py (IKE fields) -> features/pipeline.py
(ESP metadata, parquet) -> staging queue -> kafka/producer.py thread -> Kafka.

A PCAP is processed once it is complete:
  * on the inotify close-after-write event (tcpdump closed the file), or
  * after it is moved/renamed into the directory, or
  * when its size has not changed for --settle-delay seconds (fallback for
    platforms without close events).
"""

from __future__ import annotations

import argparse
import importlib.util
import logging
import os
import queue
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from watchdog.events import FileSystemEventHandler  # noqa: E402
from watchdog.observers import Observer  # noqa: E402

from features.schema import IPsecFeatureRow  # noqa: E402

DEFAULT_CAPTURES_DIR = os.getenv("CAPTURES_DIR") or str(ROOT / os.getenv("PCAP_DIR", "capture/pcaps"))
PCAP_SUFFIXES = (".pcap",)

# Unbounded queue of Kafka envelopes ready to publish. Drained by the producer
# thread (kafka/producer.py run_producer_loop) running in this same process.
STAGING_QUEUE: "queue.Queue[dict]" = queue.Queue()


def _setup_logging(level: str) -> logging.Logger:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=getattr(logging, level.upper(), logging.INFO),
        stream=sys.stdout,
    )
    logging.getLogger("kafka").setLevel(logging.WARNING)
    return logging.getLogger("watcher")


def load_producer_module():
    """
    Import kafka/producer.py by file path: the name `kafka.producer` belongs to
    the kafka-python library, which shadows this repo's kafka/ directory.
    """
    name = "sentry_kafka_producer"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "kafka" / "producer.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ── Per-PCAP processing ──────────────────────────────────────────────────────

def _run_ike_parser(pcap_path: Path, log: logging.Logger) -> Optional[dict]:
    try:
        from features.ike_parser import parse_ike_pcap

        result = parse_ike_pcap(str(pcap_path))
    except Exception as exc:
        log.error("ike_parser raised %s on %s: %s", type(exc).__name__, pcap_path.name, exc)
        return None
    if not result or not result.get("ike_packet_count"):
        log.warning("no IKE packets found in %s", pcap_path.name)
        return None
    return result


def _run_pipeline(pcap_path: Path, ike_fields: dict, log: logging.Logger) -> Optional[IPsecFeatureRow]:
    try:
        from features.pipeline import extract_features

        return extract_features(str(pcap_path), ike_fields)
    except Exception as exc:
        log.error("pipeline raised %s on %s: %s", type(exc).__name__, pcap_path.name, exc)
        return None


def process_pcap(pcap_path: Path, log: logging.Logger, source: str = "watcher",
                 staging_queue: "queue.Queue[dict]" = STAGING_QUEUE) -> bool:
    """Extract one PCAP and enqueue its feature row. Returns True on success."""
    session_id = pcap_path.stem
    log.info("TRIGGER | session_id=%s | source=%s", session_id, source)
    t0 = time.monotonic()

    ike_fields = _run_ike_parser(pcap_path, log)
    if ike_fields is None:
        log.error("SKIP | session_id=%s | reason=ike_parse_failed", session_id)
        return False
    row = _run_pipeline(pcap_path, ike_fields, log)
    if row is None:
        log.error("SKIP | session_id=%s | reason=pipeline_failed", session_id)
        return False

    staging_queue.put({
        "schema_version": "1.0",
        "source": source,
        "enqueued_at": datetime.now(timezone.utc).isoformat(),
        "feature_row": row.to_dict(),
    })
    log.info(
        "ENQUEUED | session_id=%s | esp_packets=%d | queue_depth=%d | %.0f ms",
        session_id, row.esp_packet_count, staging_queue.qsize(), (time.monotonic() - t0) * 1000,
    )
    return True


# ── Live watching ────────────────────────────────────────────────────────────

class PcapHandler(FileSystemEventHandler):
    """
    Schedules each new PCAP for processing once it is complete. Events are only
    recorded here; the actual work runs on a separate worker thread so slow
    parsing never blocks the observer.
    """

    def __init__(self, log: logging.Logger, settle_delay: float) -> None:
        super().__init__()
        self.log = log
        self.settle_delay = settle_delay
        self._lock = threading.Lock()
        self._pending: dict[str, tuple[int, float]] = {}  # path -> (size, last change)
        self._done: set[str] = set()
        self.ready: "queue.Queue[Path]" = queue.Queue()

    @staticmethod
    def _is_pcap(path: str) -> bool:
        return path.lower().endswith(PCAP_SUFFIXES)

    def _mark_ready(self, path: str) -> None:
        with self._lock:
            if path in self._done:
                return
            self._done.add(path)
            self._pending.pop(path, None)
        self.ready.put(Path(path))

    def _track(self, path: str) -> None:
        with self._lock:
            if path not in self._done:
                self._pending[path] = (-1, time.monotonic())

    def on_created(self, event) -> None:
        if not event.is_directory and self._is_pcap(event.src_path):
            with self._lock:
                self._done.discard(event.src_path)  # a re-capture with the same name is new work
            self._track(event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory and self._is_pcap(event.src_path):
            self._track(event.src_path)

    def on_closed(self, event) -> None:  # inotify IN_CLOSE_WRITE (Linux)
        if not event.is_directory and self._is_pcap(event.src_path):
            self._mark_ready(event.src_path)

    def on_moved(self, event) -> None:
        if not event.is_directory and self._is_pcap(event.dest_path):
            self._mark_ready(event.dest_path)

    def poll_settled(self) -> None:
        """Fallback: mark files whose size stopped changing for settle_delay seconds."""
        now = time.monotonic()
        with self._lock:
            items = list(self._pending.items())
        for path, (size, changed_at) in items:
            try:
                current = os.path.getsize(path)
            except OSError:
                with self._lock:
                    self._pending.pop(path, None)
                continue
            if current != size:
                with self._lock:
                    if path in self._pending:
                        self._pending[path] = (current, now)
            elif current > 0 and now - changed_at >= self.settle_delay:
                self._mark_ready(path)


def _worker(handler: PcapHandler, log: logging.Logger, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            path = handler.ready.get(timeout=0.5)
        except queue.Empty:
            continue
        if path.exists() and path.stat().st_size > 0:
            process_pcap(path, log, source="watcher")
        else:
            log.warning("File disappeared or empty before processing: %s", path.name)


def _start_producer(args, log: logging.Logger, stop: threading.Event) -> Optional[threading.Thread]:
    if args.no_kafka:
        log.warning("--no-kafka: feature rows are extracted but NOT published")
        return None
    producer_mod = load_producer_module()
    producer = producer_mod.make_producer(args.bootstrap)  # fail fast if Kafka is down
    thread = threading.Thread(
        target=producer_mod.run_producer_loop,
        kwargs={"staging_queue": STAGING_QUEUE, "bootstrap": args.bootstrap,
                "stop_event": stop, "producer": producer},
        name="kafka-producer",
        daemon=True,
    )
    thread.start()
    return thread


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="IPsec PCAP watcher — feature extraction pipeline")
    parser.add_argument("--captures-dir", default=DEFAULT_CAPTURES_DIR,
                        help=f"Directory to monitor for new .pcap files (default: {DEFAULT_CAPTURES_DIR})")
    parser.add_argument("--replay", metavar="PCAP_OR_DIR", default=None,
                        help="Process a PCAP or every PCAP in a directory, publish, then exit")
    parser.add_argument("--settle-delay", type=float, default=10.0,
                        help="Seconds a file must stop growing before it is processed when no "
                             "close event arrives (default: 10)")
    parser.add_argument("--bootstrap", default=os.getenv("KAFKA_BOOTSTRAP", "localhost:29092"))
    parser.add_argument("--no-kafka", action="store_true", help="Extract features without publishing")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args(argv)
    log = _setup_logging(args.log_level)

    stop = threading.Event()
    try:
        producer_thread = _start_producer(args, log, stop)
    except RuntimeError as exc:
        log.critical("%s", exc)
        return 1

    def _finish() -> None:
        stop.set()
        if producer_thread is not None:
            producer_thread.join(timeout=30)
            if producer_thread.is_alive():
                log.error("Producer did not finish within 30 s — %d rows unpublished", STAGING_QUEUE.qsize())

    # -- Replay mode
    if args.replay:
        target = Path(args.replay)
        if target.is_file():
            pcaps = [target]
        elif target.is_dir():
            pcaps = sorted(p for p in target.rglob("*") if p.suffix.lower() in PCAP_SUFFIXES)
        else:
            log.error("--replay path does not exist: %s", target)
            _finish()
            return 1
        log.info("REPLAY | %d PCAPs", len(pcaps))
        ok = sum(process_pcap(p, log, source="replay") for p in pcaps)
        _finish()
        log.info("REPLAY DONE | ok=%d failed=%d", ok, len(pcaps) - ok)
        return 0 if ok == len(pcaps) else 1

    # -- Live watch mode
    captures_dir = Path(args.captures_dir)
    captures_dir.mkdir(parents=True, exist_ok=True)
    handler = PcapHandler(log=log, settle_delay=args.settle_delay)
    observer = Observer()
    observer.schedule(handler, str(captures_dir), recursive=False)
    observer.start()
    worker = threading.Thread(target=_worker, args=(handler, log, stop), name="pcap-worker", daemon=True)
    worker.start()
    log.info("WATCHING | dir=%s | settle_delay=%.1fs | kafka=%s",
             captures_dir.resolve(), args.settle_delay, "off" if args.no_kafka else args.bootstrap)

    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        while not stop.is_set():
            handler.poll_settled()
            if producer_thread is not None and not producer_thread.is_alive():
                log.critical("Kafka producer thread died — exiting")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Interrupted")
    observer.stop()
    observer.join()
    stop.set()
    worker.join(timeout=60)
    _finish()
    log.info("Watcher stopped | unpublished=%d", STAGING_QUEUE.qsize())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
