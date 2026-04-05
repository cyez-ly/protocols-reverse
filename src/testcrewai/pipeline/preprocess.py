from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
import shutil
from statistics import mean, pstdev
from typing import Dict, List, Optional, Tuple

from testcrewai.adapters.common import cluster_messages_by_length, printable_ratio, shannon_entropy
from testcrewai.models import MessageCluster, SessionFeature, TrafficProfile
from testcrewai.tools.shell_runner import ShellRunner
from testcrewai.tools.protocol_tools import TsharkTool
from testcrewai.utils.io import write_json

_PCAP_MAGIC_HEADERS = {
    b"\xd4\xc3\xb2\xa1",  # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4",  # big-endian, microsecond
    b"\x4d\x3c\xb2\xa1",  # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d",  # big-endian, nanosecond
}
_PCAPNG_MAGIC_HEADER = b"\x0a\x0d\x0d\x0a"


def _safe_mean(values: List[float]) -> float:
    return float(mean(values)) if values else 0.0


def _safe_std(values: List[float]) -> float:
    return float(pstdev(values)) if len(values) > 1 else 0.0


def _detect_extension_format(file_path: Path) -> str:
    suffix = file_path.suffix.lower()
    if suffix == ".pcap":
        return "pcap"
    if suffix == ".pcapng":
        return "pcapng"
    return "unknown"


def _read_capture_magic(file_path: Path) -> bytes:
    try:
        return file_path.read_bytes()[:4]
    except Exception:
        return b""


def _detect_capture_format_from_magic(file_path: Path) -> str:
    header = _read_capture_magic(file_path)
    if header in _PCAP_MAGIC_HEADERS:
        return "pcap"
    if header == _PCAPNG_MAGIC_HEADER:
        return "pcapng"
    return "unknown"


def _detect_capture_format(file_path: Path) -> str:
    # 优先根据文件头判定格式；很多样本文件后缀名并不可靠。
    magic_format = _detect_capture_format_from_magic(file_path)
    if magic_format != "unknown":
        return magic_format
    return _detect_extension_format(file_path)


def _has_valid_capture_magic(file_path: Path, capture_format: str) -> bool:
    header = _read_capture_magic(file_path)
    if not header:
        return False

    if capture_format == "pcap":
        return header in _PCAP_MAGIC_HEADERS
    if capture_format == "pcapng":
        return header == _PCAPNG_MAGIC_HEADER
    return True


def _extract_messages_with_scapy(file_path: Path, max_samples: int = 300) -> Tuple[List[bytes], List[SessionFeature], Dict[str, int], List[str]]:
    notes: List[str] = []
    protocols: Dict[str, int] = defaultdict(int)

    try:
        from scapy.all import BOOTP, DHCP, DNS, IP, TCP, UDP, Raw, rdpcap  # type: ignore
    except Exception:
        notes.append("scapy 不可用，跳过基于数据包的解析")
        return [], [], {}, notes

    try:
        packets = rdpcap(str(file_path))
    except Exception as exc:
        notes.append(f"scapy 解析失败: {exc}")
        return [], [], {}, notes

    payloads: List[bytes] = []
    session_store: Dict[str, Dict[str, float]] = defaultdict(
        lambda: {
            "packet_count": 0,
            "payload_sum": 0.0,
            "forward": 0,
            "reverse": 0,
            "protocol": "unknown",
        }
    )

    for pkt in packets:
        payload = b""

        # 优先拿显式原始负载；若没有原始层，再回退到传输层负载。
        # DHCP/BOOTP 这类流量常见“有业务数据但无原始层”的情况。
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
        elif pkt.haslayer(UDP):
            try:
                payload = bytes(pkt[UDP].payload)
            except Exception:
                payload = b""
        elif pkt.haslayer(TCP):
            try:
                payload = bytes(pkt[TCP].payload)
            except Exception:
                payload = b""

        if payload and len(payloads) < max_samples:
            payloads.append(payload)

        if pkt.haslayer(TCP):
            protocol = "tcp"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            protocol = "udp"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        else:
            protocol = "other"
            sport = 0
            dport = 0

        protocols[protocol] += 1
        if pkt.haslayer(DNS):
            protocols["dns"] += 1
        if pkt.haslayer(DHCP) or pkt.haslayer(BOOTP):
            protocols["dhcp"] += 1
        if protocol == "udp" and (sport == 67 or sport == 68 or dport == 67 or dport == 68):
            protocols["dhcp"] += 1
        if protocol == "udp" and (sport == 123 or dport == 123):
            protocols["ntp"] += 1
        if protocol == "udp" and payload and _looks_like_dns_payload(payload):
            protocols["dns"] += 1

        if pkt.haslayer(IP):
            src = str(pkt[IP].src)
            dst = str(pkt[IP].dst)
        else:
            src = "unknown"
            dst = "unknown"

        endpoint_a = f"{src}:{sport}"
        endpoint_b = f"{dst}:{dport}"
        canonical = sorted([endpoint_a, endpoint_b])
        session_id = f"{protocol}|{canonical[0]}<->{canonical[1]}"

        item = session_store[session_id]
        item["packet_count"] += 1
        item["payload_sum"] += float(len(payload))
        item["protocol"] = protocol

        if endpoint_a == canonical[0]:
            item["forward"] += 1
        else:
            item["reverse"] += 1

    session_features: List[SessionFeature] = []
    for session_id, values in session_store.items():
        packet_count = int(values["packet_count"])
        if packet_count <= 0:
            continue
        direction_ratio = values["forward"] / max(1, values["forward"] + values["reverse"])
        session_features.append(
            SessionFeature(
                session_id=session_id,
                protocol=str(values["protocol"]),
                packet_count=packet_count,
                mean_payload_len=values["payload_sum"] / packet_count,
                direction_ratio=direction_ratio,
            )
        )

    return payloads, session_features, dict(protocols), notes


_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]+$")


def _looks_like_dns_payload(payload: bytes) -> bool:
    # 根据 DNS 协议标准，报头固定 12 字节，短于该长度可直接排除。
    if len(payload) < 12:
        return False

    flags = int.from_bytes(payload[2:4], "big")
    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    nscount = int.from_bytes(payload[8:10], "big")
    arcount = int.from_bytes(payload[10:12], "big")

    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F
    total_records = qdcount + ancount + nscount + arcount

    if opcode > 5 or rcode > 10:
        return False
    if total_records <= 0 or total_records > 100:
        return False
    if qdcount > 20:
        return False

    # 当存在查询问题区时，对域名编码做轻量合理性检查，降低误判率。
    if qdcount > 0 and len(payload) > 13:
        index = 12
        label_budget = 0
        while index < len(payload) and label_budget < 20:
            label_len = payload[index]
            index += 1
            if label_len == 0:
                break
            if label_len > 63:
                return False
            if index + label_len > len(payload):
                return False
            label = payload[index : index + label_len]
            if not all(33 <= ch <= 126 for ch in label):
                return False
            index += label_len
            label_budget += 1

    return True


def _parse_tshark_hex_tokens(text: str) -> List[bytes]:
    values: List[bytes] = []
    if not text:
        return values

    for token in re.split(r"[\s,;]+", text.strip()):
        cleaned = token.strip().replace(":", "")
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        if not cleaned:
            continue
        if len(cleaned) % 2 != 0:
            continue
        if _HEX_ONLY_RE.match(cleaned) is None:
            continue
        try:
            decoded = bytes.fromhex(cleaned)
        except ValueError:
            continue
        if decoded:
            values.append(decoded)
    return values


def _extract_messages_with_tshark(file_path: Path, timeout_sec: int = 90, max_samples: int = 300) -> Tuple[List[bytes], List[str]]:
    notes: List[str] = []
    if shutil.which("tshark") is None:
        notes.append("tshark 不可用，无法执行 payload 提取兜底")
        return [], notes

    runner = ShellRunner()
    payloads: List[bytes] = []
    seen_hex: set[str] = set()
    candidate_fields = ["udp.payload", "tcp.payload", "data.data", "data"]

    for field_name in candidate_fields:
        command = ["tshark", "-r", str(file_path), "-T", "fields", "-e", field_name]
        result = runner.run(command=command, timeout_sec=timeout_sec)
        if result.return_code != 0:
            notes.append(f"tshark 字段 {field_name} 提取失败: {result.stderr or 'unknown error'}")
            continue

        field_samples = 0
        for line in result.stdout.splitlines():
            decoded_values = _parse_tshark_hex_tokens(line)
            for value in decoded_values:
                hex_value = value.hex()
                if hex_value in seen_hex:
                    continue
                seen_hex.add(hex_value)
                payloads.append(value)
                field_samples += 1
                if len(payloads) >= max_samples:
                    break
            if len(payloads) >= max_samples:
                break

        if field_samples > 0:
            notes.append(f"通过 tshark 字段 '{field_name}' 的 payload 兜底成功，samples={field_samples}")
        else:
            notes.append(f"tshark 字段 '{field_name}' 未返回 payload 字节")

        if len(payloads) >= max_samples:
            break

    if payloads:
        notes.append(f"tshark payload 兜底总样本数={len(payloads)}")
    else:
        notes.append("tshark payload 提取未返回任何字节")
    return payloads, notes


def _extract_protocols_with_tshark(file_path: Path, timeout_sec: int = 90) -> Tuple[Dict[str, int], List[str]]:
    notes: List[str] = []
    protocols: Dict[str, int] = defaultdict(int)
    if shutil.which("tshark") is None:
        notes.append("tshark 不可用，无法执行协议识别兜底")
        return {}, notes

    runner = ShellRunner()
    command = ["tshark", "-r", str(file_path), "-T", "fields", "-e", "frame.protocols"]
    result = runner.run(command=command, timeout_sec=timeout_sec)
    if result.return_code != 0:
        notes.append(f"tshark frame.protocols 提取失败: {result.stderr or 'unknown error'}")
        return {}, notes

    for line in result.stdout.splitlines():
        normalized = line.strip().lower()
        if not normalized:
            continue
        for token in re.split(r"[:;,\s]+", normalized):
            token = token.strip()
            if not token:
                continue
            if token in {"tcp", "udp", "dns", "dhcp", "bootp", "ntp", "icmp", "http", "tls", "quic"}:
                protocols[token] += 1

    notes.append(f"tshark frame.protocols 共提取到 {len(protocols)} 个协议线索")
    return dict(protocols), notes


def _classify_protocol_style(mean_entropy: float, mean_printable: float) -> str:
    if mean_entropy == 0.0 and mean_printable == 0.0:
        return "unknown"
    if mean_printable >= 0.8 and mean_entropy <= 5.2:
        return "text"
    if mean_printable <= 0.35 and mean_entropy >= 6.2:
        return "binary"
    return "hybrid"


def _build_message_clusters(payloads: List[bytes]) -> List[MessageCluster]:
    clusters = cluster_messages_by_length(payloads)
    result: List[MessageCluster] = []

    for cluster_id, messages in clusters.items():
        lengths = [len(msg) for msg in messages]
        result.append(
            MessageCluster(
                cluster_id=cluster_id,
                sample_count=len(messages),
                mean_length=round(_safe_mean([float(v) for v in lengths]), 3),
                representative_lengths=sorted(set(lengths))[:8],
            )
        )
    return result


def _downselect_payloads_for_reverse(
    payloads: List[bytes],
    *,
    min_total_samples: int = 40,
    min_cluster_size: int = 3,
    max_clusters: int = 4,
    target_coverage: float = 0.85,
) -> Tuple[List[bytes], List[str]]:
    if len(payloads) < min_total_samples:
        return payloads, []

    buckets: Dict[int, List[bytes]] = defaultdict(list)
    for payload in payloads:
        buckets[len(payload)].append(payload)

    if len(buckets) <= max_clusters:
        return payloads, []

    ranked = sorted(buckets.items(), key=lambda item: (-len(item[1]), item[0]))
    total = len(payloads)
    selected_lengths: List[int] = []
    selected_count = 0

    for length, members in ranked:
        if len(members) < min_cluster_size and selected_lengths:
            continue
        selected_lengths.append(length)
        selected_count += len(members)
        coverage = selected_count / max(1, total)
        if len(selected_lengths) >= max_clusters or coverage >= target_coverage:
            break

    if not selected_lengths:
        return payloads, []

    selected_set = set(selected_lengths)
    selected_payloads = [item for item in payloads if len(item) in selected_set]
    if len(selected_payloads) >= max(8, int(len(payloads) * 0.55)):
        notes = [
            (
                "已启用 payload down-selection（降采样）以提升逆向稳定性: "
                f"kept_lengths={sorted(selected_lengths)}, "
                f"kept={len(selected_payloads)}/{len(payloads)}"
            )
        ]
        return selected_payloads, notes

    return payloads, []


class PreprocessAgentStage:
    # 预处理阶段：抽取报文负载、统计特征并生成流量画像文件。
    def __init__(self, tshark_tool: Optional[TsharkTool] = None) -> None:
        self.tshark_tool = tshark_tool or TsharkTool()

    def run(self, pcap_path: str, output_dir: str, timeout_sec: int, python_bin: str, logger) -> TrafficProfile:
        # 输入可以是 pcap/pcapng；若工具缺失会自动走兜底路径。
        input_path = Path(pcap_path)
        extension_format = _detect_extension_format(input_path)
        magic_format = _detect_capture_format_from_magic(input_path)
        profile = TrafficProfile(input_file=str(input_path), capture_format=_detect_capture_format(input_path))
        is_capture_format = profile.capture_format in {"pcap", "pcapng"}

        if (
            magic_format in {"pcap", "pcapng"}
            and extension_format in {"pcap", "pcapng"}
            and magic_format != extension_format
        ):
            profile.notes.append(
                (
                    "抓包文件后缀与文件头不一致: "
                    f"suffix={extension_format}, magic={magic_format}; 将以 magic 判定为准"
                )
            )

        if is_capture_format and not _has_valid_capture_magic(input_path, profile.capture_format):
            suffix_hint = input_path.suffix.lower() or "(no suffix)"
            profile.errors.append(
                (
                    f"输入文件后缀为 {suffix_hint}，但 pcap/pcapng magic header 非法。"
                    "文件可能损坏，或并非真实抓包文件。"
                )
            )
            profile.notes.append("预处理已中止：pcap/pcapng 文件头无效")
            profile_path = Path(output_dir) / "traffic_profile.json"
            write_json(profile_path, profile)
            logger.info("Preprocess completed -> %s", profile_path)
            return profile

        tshark_result = self.tshark_tool.run(
            input_path=str(input_path),
            output_dir=output_dir,
            extra_args={"timeout_sec": str(timeout_sec), "python_bin": python_bin},
        )
        if tshark_result.success:
            profile.notes.append("已收集 tshark 摘要")
            summary_text = tshark_result.data.get("summary", "").lower()
            for keyword in ["tcp", "udp", "http", "dns", "tls", "dhcp", "bootp"]:
                if keyword in summary_text and keyword not in profile.protocols_observed:
                    profile.protocols_observed.append(keyword)
        else:
            profile.notes.append(f"tshark 不可用或执行失败: {tshark_result.error}")

        # 主路径：scapy 提取消息与会话；若失败则由后续 tshark 兜底。
        payloads, session_features, protocols, parse_notes = _extract_messages_with_scapy(input_path)
        profile.notes.extend(parse_notes)
        profile.session_features = session_features
        profile.session_count = len(session_features)

        tshark_protocols, tshark_protocol_notes = _extract_protocols_with_tshark(
            input_path,
            timeout_sec=timeout_sec,
        )
        profile.notes.extend(tshark_protocol_notes)
        for name, count in tshark_protocols.items():
            protocols[name] = protocols.get(name, 0) + count

        if not payloads:
            # 兜底路径：按字段提取业务数据十六进制并反解为字节样本。
            tshark_payloads, tshark_notes = _extract_messages_with_tshark(
                input_path,
                timeout_sec=timeout_sec,
                max_samples=300,
            )
            profile.notes.extend(tshark_notes)
            if tshark_payloads:
                payloads = tshark_payloads

        if protocols:
            for key in sorted(protocols.keys()):
                if key not in profile.protocols_observed:
                    profile.protocols_observed.append(key)

        if not payloads:
            if is_capture_format:
                # 真实抓包但提取不到消息，直接记为错误，供后续阶段降级处理。
                profile.protocol_style = "unknown"
                profile.errors.append(
                    "未从抓包中提取到可解析数据包。请检查文件完整性以及 tshark/scapy 是否可用。"
                )
            else:
                # 非抓包输入时，允许按文件字节窗口构造“伪消息”保持流程可运行。
                raw = input_path.read_bytes() if input_path.exists() else b""
                if raw:
                    window = raw[:4096]
                    profile.packet_count = 0
                    profile.min_packet_length = len(window)
                    profile.max_packet_length = len(window)
                    profile.avg_packet_length = float(len(window))
                    profile.std_packet_length = 0.0
                    profile.mean_entropy = shannon_entropy(list(window))
                    profile.mean_printable_ratio = printable_ratio(window)
                    profile.protocol_style = _classify_protocol_style(profile.mean_entropy, profile.mean_printable_ratio)
                    profile.sample_messages_hex = [window[:128].hex()]
                    profile.message_clusters = _build_message_clusters([window[:128]])
                    profile.notes.append("fallback 模式：使用文件字节窗口作为伪消息")
                else:
                    profile.errors.append("抓包文件为空或读取失败")
        else:
            # 为逆向稳定性做降采样，优先保留主长度簇，减少噪声长度干扰。
            payloads, downselect_notes = _downselect_payloads_for_reverse(payloads)
            profile.notes.extend(downselect_notes)

            lengths = [len(payload) for payload in payloads]
            entropies = [shannon_entropy(list(payload)) for payload in payloads if payload]
            printable_ratios = [printable_ratio(payload) for payload in payloads if payload]

            profile.packet_count = len(payloads)
            profile.min_packet_length = min(lengths)
            profile.max_packet_length = max(lengths)
            profile.avg_packet_length = round(_safe_mean([float(v) for v in lengths]), 3)
            profile.std_packet_length = round(_safe_std([float(v) for v in lengths]), 3)
            profile.mean_entropy = round(_safe_mean(entropies), 3)
            profile.mean_printable_ratio = round(_safe_mean(printable_ratios), 3)
            profile.protocol_style = _classify_protocol_style(profile.mean_entropy, profile.mean_printable_ratio)
            profile.sample_messages_hex = [payload.hex() for payload in payloads[:120]]
            profile.message_clusters = _build_message_clusters(payloads)

        profile_path = Path(output_dir) / "traffic_profile.json"
        write_json(profile_path, profile)
        logger.info("Preprocess completed -> %s", profile_path)
        return profile
