from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Iterable
from urllib.parse import quote

import requests


BASE_RAW_URL = "https://gitlab.com/wireshark/wireshark/-/raw/master/"
SOURCE_NAME = "Wireshark test captures (GitLab)"
SOURCE_HOME = "https://gitlab.com/wireshark/wireshark/-/tree/master/test/captures"


@dataclass(frozen=True)
class DatasetItem:
    dataset_id: str
    protocol: str
    popularity: str
    encoding: str
    relative_path: str
    notes: str

    @property
    def source_url(self) -> str:
        return BASE_RAW_URL + quote(self.relative_path, safe="/")

    @property
    def output_filename(self) -> str:
        base_name = Path(self.relative_path).name
        if base_name.endswith(".gz"):
            base_name = base_name[:-3]
        return f"{self.dataset_id}__{base_name}"


DATASET_PLAN: tuple[DatasetItem, ...] = (
    # Common + text (larger captures than tiny unit-test samples)
    DatasetItem(
        "http_tls_challenge_stream",
        "HTTP over TLS (mixed stream)",
        "common",
        "text",
        "test/captures/challenge01_ooo_stream.pcapng.gz",
        "Large mixed HTTP/TLS stream with rich message diversity.",
    ),
    DatasetItem(
        "sip_rtp_long",
        "SIP + RTP",
        "common",
        "text",
        "test/captures/sip-rtp.pcapng",
        "Large SIP signaling with RTP media packets.",
    ),
    DatasetItem(
        "grpc_web_bulk",
        "gRPC-Web / HTTP",
        "common",
        "text",
        "test/captures/grpc_web.pcapng.gz",
        "gRPC-Web style traffic with many messages.",
    ),
    # Common + binary
    DatasetItem(
        "dns_mdns_lan",
        "DNS + mDNS",
        "common",
        "binary",
        "test/captures/dns-mdns.pcap",
        "Large LAN name-resolution traffic.",
    ),
    DatasetItem(
        "quic_follow_multistream",
        "QUIC",
        "common",
        "binary",
        "test/captures/quic_follow_multistream.pcapng",
        "Large QUIC multistream capture.",
    ),
    DatasetItem(
        "http2_follow_multistream",
        "HTTP/2",
        "common",
        "binary",
        "test/captures/http2_follow_multistream.pcapng",
        "HTTP/2 over TLS with many frames/streams.",
    ),
    DatasetItem(
        "tls_fragmented_handshakes",
        "TLS (fragmented handshakes)",
        "common",
        "binary",
        "test/captures/tls-fragmented-handshakes.pcap.gz",
        "Large TLS handshake-fragmentation sample with high packet count.",
    ),
    # Uncommon + text
    DatasetItem(
        "netperfmeter_flow",
        "NetPerfMeter",
        "uncommon",
        "text",
        "test/captures/netperfmeter.pcapng.gz",
        "Large application/control flow with many packets.",
    ),
    DatasetItem(
        "grpc_stream_reassembly",
        "gRPC stream reassembly",
        "uncommon",
        "text",
        "test/captures/grpc_stream_reassembly_sample.pcapng.gz",
        "gRPC stream reassembly scenario with richer sequence context.",
    ),
    # Uncommon + binary
    DatasetItem(
        "opcua_signed_heavy",
        "OPC UA (signed)",
        "uncommon",
        "binary",
        "test/captures/opcua-signed.pcapng",
        "Industrial protocol sample with larger packet volume.",
    ),
    DatasetItem(
        "opcua_encrypted_chunk_keys",
        "OPC UA (encrypted + chunking)",
        "uncommon",
        "binary",
        "test/captures/opcua-encrypted_with_chunking_with_keys.pcapng",
        "Encrypted/chunked OPC UA trace with key material metadata.",
    ),
    DatasetItem(
        "logistics_multicast",
        "Logistics multicast",
        "uncommon",
        "binary",
        "test/captures/logistics_multicast.pcapng",
        "Large multicast capture with mixed uncommon protocols.",
    ),
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ensure_dirs(root: Path) -> None:
    for popularity in ("common", "uncommon"):
        for encoding in ("text", "binary"):
            (root / popularity / encoding).mkdir(parents=True, exist_ok=True)
    (root / "manifests").mkdir(parents=True, exist_ok=True)


def _download_bytes(url: str, timeout_sec: int) -> bytes:
    response = requests.get(url, timeout=timeout_sec)
    response.raise_for_status()
    return response.content


def _decode_if_gzip(raw_data: bytes, source_path: str) -> bytes:
    if source_path.endswith(".gz"):
        return gzip.decompress(raw_data)
    return raw_data


def _count_packets(capture_path: Path) -> int:
    try:
        output = subprocess.check_output(
            ["tshark", "-r", str(capture_path), "-T", "fields", "-e", "frame.number"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=60,
        )
        return len([line for line in output.splitlines() if line.strip()])
    except Exception:
        return -1


def _clean_old_captures(root: Path) -> None:
    for popularity in ("common", "uncommon"):
        for encoding in ("text", "binary"):
            folder = root / popularity / encoding
            if not folder.exists():
                continue
            for item in folder.iterdir():
                if item.is_file():
                    item.unlink()


def _iter_selected(items: Iterable[DatasetItem], only: set[str]) -> list[DatasetItem]:
    if not only:
        return list(items)
    return [item for item in items if item.dataset_id in only]


def main() -> int:
    parser = argparse.ArgumentParser(description="Download and organize protocol reverse-engineering datasets.")
    parser.add_argument("--root", default="datasets", help="Output root directory (default: datasets)")
    parser.add_argument("--timeout-sec", type=int, default=45, help="Per-file HTTP timeout in seconds")
    parser.add_argument("--force", action="store_true", help="Re-download even if local file exists")
    parser.add_argument("--clean-old", action="store_true", help="Delete old capture files before download")
    parser.add_argument("--only", default="", help="Comma-separated dataset_id subset")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    _ensure_dirs(root)
    if args.clean_old:
        _clean_old_captures(root)

    only = {item.strip() for item in args.only.split(",") if item.strip()}
    selected = _iter_selected(DATASET_PLAN, only)

    downloaded_records: list[dict[str, str | int]] = []
    failed_records: list[dict[str, str]] = []

    for item in selected:
        output_path = root / item.popularity / item.encoding / item.output_filename
        if output_path.exists() and not args.force:
            raw_bytes = output_path.read_bytes()
            packet_count = _count_packets(output_path)
            downloaded_records.append(
                {
                    "dataset_id": item.dataset_id,
                    "protocol": item.protocol,
                    "popularity": item.popularity,
                    "encoding": item.encoding,
                    "source_name": SOURCE_NAME,
                    "source_home": SOURCE_HOME,
                    "source_path": item.relative_path,
                    "source_url": item.source_url,
                    "local_path": str(output_path.relative_to(root)),
                    "size_bytes": len(raw_bytes),
                    "packet_count": packet_count,
                    "sha256": _sha256_bytes(raw_bytes),
                    "notes": item.notes + " (cached)",
                }
            )
            print(f"[SKIP] {item.dataset_id} -> {output_path}")
            continue

        try:
            remote_bytes = _download_bytes(item.source_url, timeout_sec=args.timeout_sec)
            local_bytes = _decode_if_gzip(remote_bytes, item.relative_path)
            output_path.write_bytes(local_bytes)
            packet_count = _count_packets(output_path)
            downloaded_records.append(
                {
                    "dataset_id": item.dataset_id,
                    "protocol": item.protocol,
                    "popularity": item.popularity,
                    "encoding": item.encoding,
                    "source_name": SOURCE_NAME,
                    "source_home": SOURCE_HOME,
                    "source_path": item.relative_path,
                    "source_url": item.source_url,
                    "local_path": str(output_path.relative_to(root)),
                    "size_bytes": len(local_bytes),
                    "packet_count": packet_count,
                    "sha256": _sha256_bytes(local_bytes),
                    "notes": item.notes,
                }
            )
            print(f"[OK] {item.dataset_id} -> {output_path}")
        except Exception as exc:  # pragma: no cover - network/availability dependent
            failed_records.append(
                {
                    "dataset_id": item.dataset_id,
                    "source_url": item.source_url,
                    "error": str(exc),
                }
            )
            print(f"[FAIL] {item.dataset_id}: {exc}")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    json_payload = {
        "generated_at_utc": timestamp,
        "source_name": SOURCE_NAME,
        "source_home": SOURCE_HOME,
        "total_planned": len(selected),
        "downloaded_or_cached": len(downloaded_records),
        "failed": len(failed_records),
        "records": downloaded_records,
        "failures": failed_records,
    }

    manifests_dir = root / "manifests"
    (manifests_dir / "dataset_index.json").write_text(
        json.dumps(json_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    csv_fields = [
        "dataset_id",
        "protocol",
        "popularity",
        "encoding",
        "source_name",
        "source_home",
        "source_path",
        "source_url",
        "local_path",
        "size_bytes",
        "packet_count",
        "sha256",
        "notes",
    ]
    with (manifests_dir / "dataset_index.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields)
        writer.writeheader()
        for row in downloaded_records:
            writer.writerow(row)

    readme = (
        "# Datasets\n\n"
        "This directory contains medium-to-large captures organized for protocol reverse engineering.\n\n"
        "Layout:\n"
        "- common/text\n"
        "- common/binary\n"
        "- uncommon/text\n"
        "- uncommon/binary\n"
        "- manifests/dataset_index.json\n"
        "- manifests/dataset_index.csv\n\n"
        "All source links, packet_count, sizes and checksums are recorded in the manifest files.\n"
    )
    (root / "README.md").write_text(readme, encoding="utf-8")

    if failed_records:
        print(f"Completed with failures: {len(failed_records)}")
        return 2
    print(f"Completed successfully: {len(downloaded_records)} datasets ready in {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
