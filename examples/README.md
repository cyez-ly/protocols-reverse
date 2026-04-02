# Examples

- `demo.pcap` / `demo.pcapng`: place your own capture file here.
- `flow_input.json`: optional trigger payload example.

Recommended sample coverage (for thesis experiments):

- Common protocols: `HTTP`, `DNS`, `TLS`, `ICMP`, `DHCP`, `NTP`, `SMB`
- Industrial protocols: `DNP3`, `Modbus`, `S7`, `BACnet`, `OPC UA`

Tip:

- Some public captures are saved as `pcapng` but named with `.pcap`.
- This project now detects by file magic header first, so suffix mismatch is allowed.

Run example:

```bash
python app/main.py --pcap examples/demo.pcap --output outputs/run_demo
```
