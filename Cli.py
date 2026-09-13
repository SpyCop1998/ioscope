#!/usr/bin/env python3
"""
iOScope — host.

Deliberately thin. Everything that touches the target process lives in
agent.js; this file picks a device, loads the agent, and renders what
comes back.

Look around
  cli.py --host H --list
  cli.py --host H --probe                    attachability map of the system
  cli.py --host H Safari --meta
  cli.py --host H Safari --modules
  cli.py --host H Safari --ranges

Ask the binary (introspection; nothing is hooked)
  cli.py --host H Safari --survey read,write
  cli.py --host H Safari --addrs open,open\\$NOCANCEL,__open
  cli.py --host H Safari --dis write,write\\$NOCANCEL --dis-count 12
  cli.py --host H Safari --testfd 1
  cli.py --host H Safari --teststat /etc/hosts

Observe
  cli.py --host H Safari --category security
  cli.py --host H Safari --category filesystem --duration 20 --out run.jsonl
  cli.py --host H -f com.apple.mobilesafari --backtrace
  cli.py --host H Safari --fdtable --duration 10

Offline
  cli.py --replay run.jsonl --category network
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from collections import Counter
from pathlib import Path

import frida

AGENT_PATH = Path(__file__).resolve().parent / "agent.js"
DEFAULT_PORT = 27042

# Attaching is generally safe; it is hot hooks that kill things. Still,
# nothing good comes of poking these even briefly.
PROBE_SKIP = {"launchd", "logd", "logd_helper", "frida-server"}

stop = threading.Event()
counts: Counter = Counter()


# --------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------
COLOR = sys.stdout.isatty()

# Kept as names, not literals: a backslash inside an f-string expression
# is a SyntaxError before Python 3.12, and this has to run on 3.9.
DIM = "\033[90m"
RESET = "\033[0m"

CAT = {
    "filesystem": ("FILE", "\033[33m"),
    "network": ("NET", "\033[36m"),
    "security": ("SEC", "\033[31m"),
    "memory": ("MEM", "\033[35m"),
    "objc": ("OBJC", "\033[34m"),
    "dyld": ("DYLD", "\033[32m"),
}


def paint(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if COLOR else text


def err(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------
# Device
# --------------------------------------------------------------------
def get_device(host: str | None):
    """
    The vphone VM is a network peer, not a USB device, so --host is the
    normal path. frida-server must bind all interfaces inside the VM:
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


def attach(device, args):
    """Returns (session, pid_if_spawned). Exits with a one-line message."""
    try:
        if args.spawn:
            pid = device.spawn([args.spawn])
            return device.attach(pid), pid
        return device.attach(resolve_target(args.target)), None
    except frida.ProcessNotFoundError:
        err(f"[!] no such process: {args.target}")
        err("    PIDs churn constantly on iOS — re-run --list")
        sys.exit(1)
    except frida.PermissionDeniedError as e:
        err(f"[!] permission denied attaching to {args.target}: {e}")
        err("    frida-server probably is not running as root")
        sys.exit(1)
    except frida.ProcessNotRespondingError as e:
        err(f"[!] injection into {args.target} failed: {e}")
        err("    the agent started and the channel died during handshake.")
        err("    check the device for a fresh JetsamEvent-*.ips:")
        err("      ls -lt /var/mobile/Library/Logs/CrashReporter/ | head")
        sys.exit(1)


# --------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------
def fmt_time(ms: int) -> str:
    secs = ms / 1000.0
    return f"{int(secs // 60):02d}:{secs % 60:06.3f}"


def fmt_addr(desc) -> str:
    if not desc:
        return "?"
    if desc.get("symbol"):
        off = desc.get("symbolOffset", "0x0")
        base = f"{desc['symbol']}+{off}" if off != "0x0" else desc["symbol"]
        return f"{desc.get('module', '?')}`{base}"
    if "module" in desc:
        return f"{desc['module']}+{desc['offset']}"
    return desc.get("raw", "?")


def render_timeline(ev: dict, show_backtrace: bool, verbose: bool) -> None:
    label, color = CAT.get(ev["category"], (ev["category"][:4].upper(), ""))

    args = ", ".join(str(a) for a in (ev.get("args") or []))
    call = f"{ev['symbol']}({args})"
    ret = ev.get("ret")
    if ret is not None:
        call += f" -> {ret}"

    line = f"{fmt_time(ev['t'])}  {paint(f'{label:<4}', color)}  {call}"

    # Caller on the same line keeps output greppable: one event, one line.
    caller = fmt_addr(ev.get("caller"))
    if not verbose:
        print(line + "   " + paint(caller, DIM))
    else:
        print(line)
        via = ev.get("via")
        extra = f" via {via}" if via and via != ev["symbol"] else ""
        print(f"{'':11} caller: {caller}  tid {ev.get('thread')}{extra}")

    if show_backtrace and ev.get("backtrace"):
        for frame in ev["backtrace"]:
            print(f"{'':11}   {fmt_addr(frame)}")


def make_sink(args, out_fh):
    def sink(ev):
        counts[ev["category"]] += 1
        if out_fh is not None:
            out_fh.write(json.dumps(ev) + "\n")
        if args.json:
            print(json.dumps(ev), flush=True)
        else:
            render_timeline(ev, args.backtrace, args.verbose)

    return sink


def make_handler(sink):
    def on_message(message, data):
        if message["type"] == "error":
            err(f"[agent error] {message.get('description')}")
            if "stack" in message:
                err(message["stack"])
            return

        payload = message.get("payload") or {}
        kind = payload.get("kind")

        if kind == "events":
            for ev in payload["events"]:
                sink(ev)
        elif kind == "agent-error":
            err(f"[agent] {payload.get('message')}")
        else:
            err(f"[agent] {payload}")

    return on_message


# --------------------------------------------------------------------
# Modes that do not need a running capture
# --------------------------------------------------------------------
def do_list(device) -> int:
    procs = sorted(device.enumerate_processes(), key=lambda x: x.pid)
    for proc in procs:
        print(f"{proc.pid:>6}  {proc.name}")
    err(f"\n{len(procs)} processes")
    return 0


def do_probe(device, limit: int | None) -> int:
    """
    Walk every process, attempt an attach, record the outcome.

    One failing daemon is a puzzle; ninety is a rule. This table is the
    practical shape of the iOS security model, derived rather than read.
    Slow: attaching to a large process can take many seconds.
    """
    procs = sorted(device.enumerate_processes(), key=lambda x: x.pid)
    if limit:
        procs = procs[:limit]

    err(f"[*] probing {len(procs)} processes — this takes a while, ctrl-c to stop\n")
    outcomes: Counter = Counter()
    rows = []

    for proc in procs:
        if stop.is_set():
            err("\n[*] stopped early")
            break
        if proc.name in PROBE_SKIP:
            outcomes["skipped"] += 1
            rows.append((proc.pid, proc.name, "skipped", ""))
            continue
        try:
            session = device.attach(proc.pid)
            session.detach()
            outcome, detail = "ok", ""
        except Exception as e:
            outcome, detail = type(e).__name__, str(e)[:52]
        outcomes[outcome] += 1
        rows.append((proc.pid, proc.name, outcome, detail))
        mark = "+" if outcome == "ok" else "-"
        print(f"{mark} {proc.pid:>6}  {proc.name:<44} {outcome} {detail}")

    err("\n--- outcomes ---")
    for name, n in outcomes.most_common():
        err(f"{n:>5}  {name}")
    return 0


def do_replay(path: str, args) -> int:
    sink = make_sink(args, None)
    wanted = set(args.category) if args.category else None
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                err(f"[!] bad line skipped: {line[:60]}")
                continue
            if wanted and ev.get("category") not in wanted:
                continue
            sink(ev)
    summarize(0.0)
    return 0


def summarize(elapsed: float) -> None:
    total = sum(counts.values())
    if total == 0:
        err("\n[*] no events. a quiet process looks identical to a broken hook —")
        err("    trigger activity in the target and try again")
        return
    err(f"\n--- {total} events in {elapsed:.1f}s ---" if elapsed else f"\n--- {total} events ---")
    for cat, n in counts.most_common():
        err(f"{n:>7}  {cat}")
    if elapsed > 0:
        err(f"{total / elapsed:>7.0f}  events/sec")


def csv(s: str | None) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()] if s else []


# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(prog="ioscope")
    p.add_argument("target", nargs="?", help="process name or pid")
    p.add_argument("--host", help="frida-server host, e.g. 192.168.64.6:27042")
    p.add_argument("-f", "--spawn", metavar="ID", help="spawn a bundle id instead of attaching")

    g = p.add_argument_group("survey the device")
    g.add_argument("--list", action="store_true", help="list processes and exit")
    g.add_argument("--probe", action="store_true", help="attachability map of every process")
    g.add_argument("--probe-limit", type=int, metavar="N", help="stop after N processes")

    g.add_argument("--backtrace-depth", type=int, default=12, metavar="N")
    g.add_argument("--deep-symbols", action="store_true",
                   help="also index full symbol tables (slow, better names)")
    g.add_argument("--fuzzy", action="store_true",
                   help="stack-scanning backtracer; returns invented frames")

    g = p.add_argument_group("ask the target (nothing is hooked)")
    g.add_argument("--meta", action="store_true", help="process metadata")
    g.add_argument("--modules", action="store_true", help="module map")
    g.add_argument("--ranges", action="store_true", help="memory map; the /proc/pid/maps stand-in")
    g.add_argument("--survey", metavar="NEEDLES", help="exports matching comma-separated substrings")
    g.add_argument("--module", metavar="NAME", help="which image to survey/addrs/dis against")
    g.add_argument("--addrs", metavar="NAMES", help="stripped addresses for comma-separated symbols")
    g.add_argument("--dis", metavar="NAMES", help="disassemble comma-separated symbols")
    g.add_argument("--dis-count", type=int, default=8, metavar="N", help="instructions per symbol")
    g.add_argument("--testfd", type=int, metavar="FD", help="prove fcntl needs the varargs marker")
    g.add_argument("--teststat", metavar="PATH", help="check the struct stat offsets")

    g = p.add_argument_group("observe")
    g.add_argument("--category", action="append",
                   help="filesystem, network, security, memory (repeatable)")
    g.add_argument("--backtrace", action="store_true", help="capture native backtraces (slow)")
    g.add_argument("--duration", type=float, metavar="SEC", help="stop after N seconds")
    g.add_argument("--fdtable", action="store_true", help="dump the fd->path map when the run ends")
    g.add_argument("--json", action="store_true", help="JSON lines on stdout instead of a timeline")
    g.add_argument("--out", metavar="FILE", help="also write JSON lines to FILE")
    g.add_argument("-v", "--verbose", action="store_true", help="caller and thread on their own line")
    g.add_argument("--replay", metavar="FILE", help="render a saved capture; no device needed")

    g.add_argument("--objc", metavar="SPEC",
                   help="class names, or globs like '-[NSURLSession *]' (comma-separated)")
    g.add_argument("--objc-depth", type=int, default=0, metavar="N",
                    help="also hook N levels of superclass")
    g.add_argument("--objc-max", type=int, default=400, metavar="N")
    g.add_argument("--objc-describe", action="store_true",
                    help="call -description on object args (runs target code in your hook)")
    g.add_argument("--objc-classes", metavar="REGEX", help="list matching classes and exit")
    g.add_argument("--objc-methods", metavar="CLASS", help="list a class's methods and exit")


    args = p.parse_args()

    # ctrl-c sets the flag; the finally block still drains and detaches.
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    if args.replay:
        return do_replay(args.replay, args)

    device = get_device(args.host)

    if args.list:
        return do_list(device)
    if args.probe:
        return do_probe(device, args.probe_limit)

    if not args.target and not args.spawn:
        p.error("need a target, -f BUNDLE_ID, --list, --probe, or --replay")

    # Spawn gates the process at its entry point, so hooks install while it
    # is frozen and you see everything from dyld onward.
    session, pid = attach(device, args)

    script = session.create_script(AGENT_PATH.read_text())
    script.on("destroyed", lambda: stop.set())

    sink = None
    out_fh = None

    try:
        script.load()
        rpc = script.exports_sync

        # ---- introspection: answer and exit, nothing hooked ----
        if args.meta:
            print(json.dumps(rpc.meta(), indent=2))
            return 0

        if args.modules:
            mods = rpc.modules()
            for m in sorted(mods, key=lambda x: int(x["base"], 16)):
                print(f"{m['base']}  {m['size']:>10}  {m['name']}")
                print(f"{'':>18}  {'':>10}  {m['path']}")
            err(f"\n{len(mods)} modules")
            return 0

        if args.ranges:
            for r in rpc.ranges():
                print(f"{r['base']}  {r['size']:>12}  {r['protection']}  {r['file'] or ''}")
            return 0

        if args.survey:
            mods = [args.module] if args.module else None
            print(json.dumps(rpc.survey(csv(args.survey), mods), indent=2))
            return 0

        if args.objc_classes:
            print(json.dumps(rpc.objcclasses(args.objc_classes, 300), indent=2))
            return 0

        if args.objc_methods:
            print(json.dumps(rpc.objcmethods(args.objc_methods), indent=2))
            return 0

        if args.addrs:
            print(json.dumps(rpc.addrs(csv(args.addrs), args.module), indent=2))
            return 0

        if args.dis:
            print(json.dumps(rpc.dis(csv(args.dis), args.dis_count, args.module), indent=2))
            return 0

        if args.testfd is not None:
            print(json.dumps(rpc.testfd(args.testfd), indent=2))
            return 0

        if args.teststat:
            out = rpc.teststat(args.teststat)
            out.pop("raw_first_128", None)  # bytes are not JSON-serialisable
            print(json.dumps(out, indent=2))
            err("\ncompare 'size=' against the real file size. a wrong offset")
            err("gives a plausible wrong number, not an error.")
            return 0

        # ---- capture ----
        if args.out:
            out_fh = open(args.out, "w")
        sink = make_sink(args, out_fh)
        script.on("message", make_handler(sink))

        result = rpc.start({
            "backtrace": args.backtrace,
            "btDepth": args.backtrace_depth,
            "fuzzy": args.fuzzy,
            "deepSymbols": args.deep_symbols,
            "categories": args.category,
            "objcFilter": args.objc,
            "objcDepth": args.objc_depth,
            "objcMax": args.objc_max,
            "objcDescribe": args.objc_describe,
        })
        c = result.get("counts", {})
        err(f"[+] {c.get('installed', 0)} hooks installed")
        if result.get("aliased"):
            err(f"[=] collapsed as duplicate addresses: {'; '.join(result['aliased'])}")
        if result.get("failed"):
            err(f"[!] not installed ({c.get('failed', 0)}): {'; '.join(result['failed'])}")

        if pid is not None:
            device.resume(pid)

        note = f" for {args.duration}s" if args.duration else " — ctrl-c to stop"
        err(f"[*] streaming{note}\n")

        started = time.time()
        stop.wait(timeout=args.duration)
        elapsed = time.time() - started

        try:
            rpc.drain()
            time.sleep(0.2)  # let the last batch arrive
        except Exception:
            pass

        if args.fdtable:
            err("\n--- fd table ---")
            try:
                for fd, path in sorted(rpc.fdtable().items(), key=lambda kv: int(kv[0])):
                    err(f"{fd:>5}  {path if path else '<unnamed>'}")
            except Exception as e:
                err(f"[!] fdtable failed: {e}")

        summarize(elapsed)
        return 0

    finally:
        if out_fh is not None:
            out_fh.close()
            err(f"[*] wrote {args.out}")
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())