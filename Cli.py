#!/usr/bin/env python3
"""
iOScope — milestone 0/1 host.

Deliberately thin. Everything that touches the target process lives in
agent.js; this file only picks a device, loads the agent, and renders
what comes back.

  python3 cli.py --host 192.168.64.6 --list
  python3 cli.py --host 192.168.64.6 --meta securityd
  python3 cli.py --host 192.168.64.6 --modules securityd
  python3 cli.py --host 192.168.64.6 securityd
  python3 cli.py --host 192.168.64.6 -f com.example.app --backtrace
  python3 cli.py --host 192.168.64.6 securityd --json > run.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path

import frida

AGENT_PATH = Path(__file__).resolve().parent / "agent.js"
DEFAULT_PORT = 27042

done = threading.Event()


# --------------------------------------------------------------------
# Device
# --------------------------------------------------------------------
def get_device(host: str | None):
    """
    Your vphone VM is a network peer, not a USB device, so --host is the
    normal path. frida-server must be listening on 0.0.0.0 inside the VM:
        frida-server -l 0.0.0.0:27042
    """
    if host:
        if ":" not in host:
            host = f"{host}:{DEFAULT_PORT}"
        return frida.get_device_manager().add_remote_device(host)
    try:
        return frida.get_usb_device(timeout=5)
    except Exception:
        return frida.get_local_device()


def resolve_target(target: str):
    return int(target) if target.isdigit() else target


# --------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------
def fmt_time(ms: int) -> str:
    secs = ms / 1000.0
    return f"{int(secs // 60):02d}:{secs % 60:06.3f}"


def fmt_addr(desc: dict) -> str:
    if desc is None:
        return "?"
    if "module" in desc:
        return f"{desc['module']} + {desc['offset']}"
    return desc.get("raw", "?")


def render_timeline(ev: dict, show_backtrace: bool) -> None:
    args = ", ".join(str(a) for a in ev.get("args", []))
    ret = ev.get("ret")
    call = f"{ev['symbol']}({args})"
    if ret is not None:
        call += f" -> {ret}"

    print(f"{fmt_time(ev['t'])}  {ev['category'].upper():<10} {call}")
    print(f"{'':11}{'':<10} caller: {fmt_addr(ev.get('caller'))}  tid {ev.get('thread')}")

    bt = ev.get("backtrace")
    if show_backtrace and bt:
        for frame in bt:
            print(f"{'':11}{'':<10}   {fmt_addr(frame)}")
    print()


def render_json(ev: dict) -> None:
    print(json.dumps(ev), flush=True)


# --------------------------------------------------------------------
# Message pump
# --------------------------------------------------------------------
def make_handler(args):
    sink = render_json if args.json else (lambda e: render_timeline(e, args.backtrace))

    def on_message(message, data):
        if message["type"] == "error":
            # Agent threw. The stack is JS line numbers in agent.js.
            print(f"[agent error] {message.get('description')}", file=sys.stderr)
            if "stack" in message:
                print(message["stack"], file=sys.stderr)
            return

        payload = message.get("payload") or {}
        kind = payload.get("kind")

        if kind == "events":
            for ev in payload["events"]:
                sink(ev)
        elif kind == "agent-error":
            print(f"[agent] {payload.get('message')}", file=sys.stderr)
        else:
            print(f"[agent] {payload}", file=sys.stderr)

    return on_message


# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(prog="ioscope")
    p.add_argument("target", nargs="?", help="process name or pid")
    p.add_argument("--host", help="frida-server host, e.g. 192.168.64.6")
    p.add_argument("-f", "--spawn", metavar="ID", help="spawn this bundle id instead of attaching")
    p.add_argument("--list", action="store_true", help="list processes and exit")
    p.add_argument("--meta", action="store_true", help="dump process metadata and exit")
    p.add_argument("--modules", action="store_true", help="dump module map and exit")
    p.add_argument("--category", action="append", help="filter (filesystem, network, security, objc)")
    p.add_argument("--backtrace", action="store_true", help="capture native backtraces (slow)")
    p.add_argument("--json", action="store_true", help="emit JSON lines instead of a timeline")
    args = p.parse_args()

    device = get_device(args.host)

    if args.list:
        for proc in sorted(device.enumerate_processes(), key=lambda x: x.pid):
            print(f"{proc.pid:>6}  {proc.name}")
        return 0

    if not args.target and not args.spawn:
        p.error("need a target, -f BUNDLE_ID, or --list")

    # Spawn gates the process at its entry point so you see everything from
    # dyld onward. Most of the interesting iOS startup work happens before
    # you could realistically attach by hand.
    pid = None
    try:
        if args.spawn:
            pid = device.spawn([args.spawn])
            session = device.attach(pid)
        else:
            session = device.attach(resolve_target(args.target))
    except frida.ProcessNotFoundError:
        print(f"[!] no such process: {args.target}", file=sys.stderr)
        return 1
    except frida.ProcessNotRespondingError as e:
        print(f"[!] injection into {args.target} failed: {e}", file=sys.stderr)
        print("    usually sandbox denial or frida-server not running as root", file=sys.stderr)
        return 1

    script = session.create_script(AGENT_PATH.read_text())
    script.on("message", make_handler(args))
    script.on("destroyed", lambda: done.set())
    script.load()

    if args.meta:
        print(json.dumps(script.exports_sync.meta(), indent=2))
        return 0

    if args.modules:
        mods = script.exports_sync.modules()
        for m in sorted(mods, key=lambda x: int(x["base"], 16)):
            print(f"{m['base']}  {m['size']:>10}  {m['name']}")
            print(f"{'':>18}  {'':>10}  {m['path']}")
        print(f"\n{len(mods)} modules", file=sys.stderr)
        return 0

    result = script.exports_sync.start(
        {
            "backtrace": args.backtrace,
            "categories": args.category,
        }
    )
    print(f"[+] hooks installed: {', '.join(result['installed']) or 'none'}", file=sys.stderr)
    if result["failed"]:
        print(f"[!] not installed: {'; '.join(result['failed'])}", file=sys.stderr)

    if pid is not None:
        device.resume(pid)

    print("[*] streaming — ctrl-c to stop\n", file=sys.stderr)
    try:
        done.wait()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            script.exports_sync.drain()
            session.detach()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())