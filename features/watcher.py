
from __future__ import annotations

import argparse
import logging
import queue
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from watchdog.events import FileCreatedEvent, FileMovedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from features.schema import IPsecFeatureRow

# 
# Logging setup

def _setup_logging(level: str) -> logging.Logger:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] watcher | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=getattr(logging, level.upper(), logging.INFO),
        stream=sys.stdout,
    )
    return logging.getLogger("watcher")


# 
# Staging queue  (module-level singleton — producer.py imports this)
# 

# Unbounded queue of IPsecFeatureRow dicts ready to publish to Kafka.
# producer.py drains this in 100 ms batching windows.
STAGING_QUEUE: queue.Queue[dict] = queue.Queue()


# 
# Pipeline caller helpers
# 

def _derive_session_id(pcap_path: Path) -> str:
    """Use the PCAP filename stem as the session_id (matches Nived's naming convention)."""
    return pcap_path.stem


def _run_ike_parser(pcap_path: Path, log: logging.Logger) -> Optional[dict]:
    """
    Call Aadi's ike_parser.parse_pcap() and return the IKE field dict.
    Returns None on any failure so the caller can skip gracefully.
    """
    try:
        from features.ike_parser import parse_pcap  # Aadi's module
        result = parse_pcap(str(pcap_path))
        if not result:
            log.warning("ike_parser returned empty result for %s", pcap_path.name)
            return None
        return result
    except ImportError:
        log.error("features.ike_parser not found — has Aadi pushed ike_parser.py yet?")
        return None
    except Exception as exc:
        log.error("ike_parser raised %s on %s: %s", type(exc).__name__, pcap_path.name, exc)
        return None


def _run_pipeline(pcap_path: Path, ike_fields: dict, log: logging.Logger) -> Optional[IPsecFeatureRow]:
    
    try:
        from features.pipeline import extract_features  # Gowri's module
        row = extract_features(str(pcap_path), ike_fields)
        if row is None:
            log.warning("pipeline returned None for %s", pcap_path.name)
            return None
        return row
    except ImportError:
        log.error("features.pipeline not found — has Gowri pushed pipeline.py yet?")
        return None
    except Exception as exc:
        log.error("pipeline raised %s on %s: %s", type(exc).__name__, pcap_path.name, exc)
        return None


# 
# Core processing function  (called from event handler AND from CLI replay)
# 

def process_pcap(pcap_path: Path, log: logging.Logger, source: str = "watcher") -> bool:
    """
    Full processing pipeline for one PCAP file.
    Returns True if a feature row was successfully enqueued, False otherwise.

    Steps:
      1. Derive session_id from filename.
      2. Run IKE parser (Aadi).
      3. Run ESP metadata pipeline (Gowri).
      4. Push serialised row to STAGING_QUEUE.
      5. Log outcome with session_id and timestamp.
    """
    triggered_at = datetime.now(timezone.utc).isoformat()
    session_id = _derive_session_id(pcap_path)

    log.info(
        "TRIGGER | session_id=%s | file=%s | source=%s | ts=%s",
        session_id, pcap_path.name, source, triggered_at,
    )

    # -- Step 1: IKE parser
    t0 = time.monotonic()
    ike_fields = _run_ike_parser(pcap_path, log)
    if ike_fields is None:
        log.error("SKIP | session_id=%s | reason=ike_parser_failed", session_id)
        return False

    # Stamp the session_id and ts into the IKE fields dict so pipeline can
    # use them without re-deriving from the filename.
    ike_fields.setdefault("session_id", session_id)
    ike_fields.setdefault("ts", time.time())

    ike_ms = (time.monotonic() - t0) * 1000
    log.debug("ike_parser OK | session_id=%s | %.1f ms", session_id, ike_ms)

    # -- Step 2: ESP metadata pipeline 
    t1 = time.monotonic()
    row = _run_pipeline(pcap_path, ike_fields, log)
    if row is None:
        log.error("SKIP | session_id=%s | reason=pipeline_failed", session_id)
        return False

    pipeline_ms = (time.monotonic() - t1) * 1000
    log.debug("pipeline OK | session_id=%s | %.1f ms", session_id, pipeline_ms)

    # -- Step 3: Enqueue 
    payload = {
        "schema_version": "1.0",
        "source": source,
        "enqueued_at": datetime.now(timezone.utc).isoformat(),
        "feature_row": row.to_dict(),
    }
    STAGING_QUEUE.put(payload)

    total_ms = (time.monotonic() - t0) * 1000
    log.info(
        "ENQUEUED | session_id=%s | queue_depth=%d | total_ms=%.1f",
        session_id, STAGING_QUEUE.qsize(), total_ms,
    )
    return True


# 
# Watchdog event handler
# 

class PcapHandler(FileSystemEventHandler):
    """
    Fires on FileCreatedEvent and FileMovedEvent (mv/rename into the watched dir).
    Ignores everything that is not a .pcap file.

    Uses a small in-memory seen-set to guard against duplicate events that
    watchdog occasionally fires when the OS flushes the write buffer in stages.
    """

    def __init__(self, log: logging.Logger, settle_delay: float = 0.5) -> None:
        super().__init__()
        self.log = log
        self.settle_delay = settle_delay  # seconds to wait after event before reading
        self._seen: set[str] = set()

    def _handle(self, path_str: str) -> None:
        path = Path(path_str)
        if path.suffix.lower() != ".pcap":
            return
        if path_str in self._seen:
            self.log.debug("DUPLICATE event ignored: %s", path.name)
            return
        self._seen.add(path_str)

        # Brief settle delay — lets tcpdump finish writing the file before we open it.
        time.sleep(self.settle_delay)

        if not path.exists():
            self.log.warning("File disappeared before processing: %s", path.name)
            self._seen.discard(path_str)
            return

        process_pcap(path, self.log, source="watcher")

    def on_created(self, event: FileCreatedEvent) -> None:
        if not event.is_directory:
            self._handle(event.src_path)

    def on_moved(self, event: FileMovedEvent) -> None:
        # tcpdump often writes to a .pcap.tmp then renames — catch the destination
        if not event.is_directory:
            self._handle(event.dest_path)


# 
# Main entry point
# 

def main() -> None:
    parser = argparse.ArgumentParser(description="IPsec PCAP watcher — feature extraction pipeline")
    parser.add_argument(
        "--captures-dir", default="/captures",
        help="Directory to monitor for new .pcap files (default: /captures)",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--settle-delay", type=float, default=0.5,
        help="Seconds to wait after a file event before reading (default: 0.5)",
    )
    parser.add_argument(
        "--replay", metavar="PCAP_OR_DIR", default=None,
        help="Replay mode: process a single PCAP or a whole directory immediately then exit",
    )
    args = parser.parse_args()

    log = _setup_logging(args.log_level)

    # -- Replay mode 
    if args.replay:
        replay_path = Path(args.replay)
        if replay_path.is_file():
            targets = [replay_path]
        elif replay_path.is_dir():
            targets = sorted(replay_path.glob("*.pcap"))
        else:
            log.error("--replay path does not exist: %s", args.replay)
            sys.exit(1)

        log.info("REPLAY MODE | %d PCAPs to process", len(targets))
        ok = fail = 0
        for pcap in targets:
            success = process_pcap(pcap, log, source="replay")
            if success:
                ok += 1
            else:
                fail += 1
        log.info("REPLAY DONE | ok=%d fail=%d | queue_depth=%d", ok, fail, STAGING_QUEUE.qsize())
        return

    # -- Live watch mode 
    captures_dir = Path(args.captures_dir)
    if not captures_dir.exists():
        log.warning("Captures directory %s does not exist — creating it", captures_dir)
        captures_dir.mkdir(parents=True, exist_ok=True)

    handler = PcapHandler(log=log, settle_delay=args.settle_delay)
    observer = Observer()
    observer.schedule(handler, str(captures_dir), recursive=False)
    observer.start()

    log.info("WATCHING | dir=%s | settle_delay=%.1fs", captures_dir, args.settle_delay)
    log.info("Press Ctrl+C to stop")

    # Graceful shutdown on SIGTERM (Docker sends this on `docker stop`)
    def _sigterm(_sig, _frame):
        log.info("SIGTERM received — shutting down watcher")
        observer.stop()

    signal.signal(signal.SIGTERM, _sigterm)

    try:
        while observer.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt — stopping watcher")
        observer.stop()

    observer.join()
    log.info("Watcher stopped. Final queue depth: %d", STAGING_QUEUE.qsize())


if __name__ == "__main__":
    main()