from __future__ import annotations

import argparse
import os
from pathlib import Path
import runpy
import sys


def _patch_netzob_impactpacket() -> str:
    """Patch missing ImpactPacket.ARP for some Netzob builds used by NetPlier."""
    try:
        from netzob.Import.PCAPImporter import ImpactPacket  # type: ignore
    except Exception as exc:
        return f"ImpactPacket import failed: {exc}"

    if hasattr(ImpactPacket, "ARP"):
        return "ImpactPacket.ARP already present"

    try:
        from impacket import ImpactPacket as ImpacketImpactPacket  # type: ignore

        if hasattr(ImpacketImpactPacket, "ARP"):
            ImpactPacket.ARP = ImpacketImpactPacket.ARP
            return "patched ImpactPacket.ARP from impacket.ImpactPacket.ARP"
    except Exception:
        pass

    class _CompatARP:
        ethertype = 0x0806

    ImpactPacket.ARP = _CompatARP
    return "patched ImpactPacket.ARP with compatibility stub"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compatibility launcher for NetPlier official main.py"
    )
    parser.add_argument("--main", required=True, help="Path to NetPlier official main.py")
    parser.add_argument("passthrough", nargs=argparse.REMAINDER, help="Arguments for NetPlier main.py")
    args = parser.parse_args()

    main_path = Path(args.main).expanduser().resolve()
    if not main_path.exists():
        print(f"[netplier-runner] main path not found: {main_path}", file=sys.stderr)
        return 2

    passthrough = list(args.passthrough)
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]

    patch_note = _patch_netzob_impactpacket()
    print(f"[netplier-runner] {patch_note}", file=sys.stderr)

    old_argv = list(sys.argv)
    old_cwd = Path.cwd()
    old_path = list(sys.path)
    try:
        os.chdir(str(main_path.parent))
        sys.path.insert(0, str(main_path.parent))
        sys.argv = [str(main_path), *passthrough]
        runpy.run_path(str(main_path), run_name="__main__")
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        if exc.code is None:
            return 0
        return 1
    finally:
        sys.argv = old_argv
        sys.path[:] = old_path
        os.chdir(str(old_cwd))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
