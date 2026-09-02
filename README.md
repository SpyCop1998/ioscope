# iOScope

> Runtime observability for iOS reverse engineers.

iOScope is a Frida-powered runtime observability tool for iOS that turns low-level
process activity into a structured, human-readable timeline.

Instead of maintaining a collection of one-off Frida scripts for filesystem,
networking, Objective-C, security APIs, and loaded modules, iOScope provides a
single observation layer for exploring what an iOS process actually does at
runtime.

```text
                    iOS PROCESS
                         │
                         ▼
                  ┌─────────────┐
                  │   iOScope   │
                  └──────┬──────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
      Objective-C     Native APIs     Modules
          │              │              │
          ├──────────────┼──────────────┤
          ▼              ▼              ▼
       Filesystem      Network       Security
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                  Event Timeline
                         │
                         ▼
                 RE Investigation
```

---

## Status

🚧 **Early development.** Milestones 0 and 1 work. One hook is implemented.

| Capability | State |
|---|---|
| Frida connection (remote) | working |
| Process attachment | working for foreground apps; daemon injection under investigation |
| Process metadata | working |
| Module enumeration | working |
| Memory range enumeration | working |
| Event schema + batching queue | working |
| JSON export | working |
| Filesystem observation | `open` and its aliases only |
| Network / Security / ObjC observation | not started |
| Native backtraces | plumbed, unverified |
| Terminal timeline | basic |

APIs and output formats will change.

---

## Why?

When reversing an iOS application, one of the first questions is:

> "What is this process actually doing?"

Answering it currently means combining several tools and custom scripts — Frida,
LLDB, `log stream`, filesystem tracing, network tools, Objective-C runtime
inspection, Mach-O analysis, manual backtrace reading.

iOScope aims to be a common runtime observation layer for those investigations.

The goal is **not** to replace Frida. The goal is to make Frida-based runtime
research faster.

---

## Development environment

Built and tested against a virtual iPhone running on Apple's
Virtualization.framework:

- Apple Silicon Mac, macOS 15+
- [`vphone-cli`](https://github.com/Lakr233/vphone-cli) /
  [`vphone-ws`](https://github.com/zqxwce/vphone-ws) — boots iOS research VMs
- Jailbreak variant (AMFI relaxed), `frida-server` listening on the VM
- Python 3.9+ on the host, `frida` Python bindings
- Frida 17.x

The VM is a complete iOS system — SpringBoard, the full daemon set, Safari and
its process family are all present. arm64e, 16KB pages, real dyld shared cache,
real sandbox.

**What is not representative:** the Jailbreak variant relaxes AMFI, so anything
observed about code signing, entitlement enforcement, or launch constraints does
not reflect a stock device. Everything else does.

---

## Installation

```bash
git clone <repo>
cd ioscope
pip3 install frida
```

On the device:

```bash
frida-server -l 0.0.0.0:27042
```

---

## Usage

```bash
# what's running
python3 cli.py --host 192.168.64.6:27042 --list

# process metadata
python3 cli.py --host 192.168.64.6:27042 --meta Safari

# module map
python3 cli.py --host 192.168.64.6:27042 --modules 1547

# live timeline
python3 cli.py --host 192.168.64.6:27042 Safari

# spawn instead of attach — see everything from dyld onward
python3 cli.py --host 192.168.64.6:27042 -f com.apple.mobilesafari

# with backtraces (slow)
python3 cli.py --host 192.168.64.6:27042 Safari --backtrace

# filtered
python3 cli.py --host 192.168.64.6:27042 Safari --category filesystem

# machine-readable
python3 cli.py --host 192.168.64.6:27042 Safari --json > run.jsonl
```

---

## Architecture

```text
┌───────────────────────────────────────┐
│           cli.py  (host)              │
│   device · attach/spawn · rendering   │
├───────────────────────────────────────┤
│          agent.js  (target)           │
├───────────────────────────────────────┤
│   guard · queue · address resolution  │
├──────────────┬──────────────┬─────────┤
│ Objective-C  │ Native APIs  │ Modules │
├──────────────┼──────────────┼─────────┤
│ Filesystem   │ Network      │Security │
└──────────────┴──────────────┴─────────┘
                       │
                       ▼
                    Frida
                       │
                       ▼
                 iOS Process
```

The split is deliberate. Everything expensive or dangerous happens in the agent;
the host only picks a device, loads the agent, and renders what comes back.

---

## Event model

Every observation becomes a normalized event.

```text
Event
├── t            (ms since agent start)
├── category
├── process
├── thread
├── symbol
├── args
├── ret
├── caller       { raw, module, offset }
└── backtrace    [ { raw, module, offset }, ... ]
```

Example:

```json
{
  "t": 2193,
  "category": "filesystem",
  "process": "Safari",
  "thread": 17,
  "symbol": "open",
  "args": ["\"/private/var/mobile/Containers/Data/...\"", "0x0"],
  "ret": 7,
  "caller": { "raw": "0x102a5c3bc", "module": "MobileSafari", "offset": "0x1a83bc" }
}
```

Addresses are reported as **module + offset**, not just raw pointers. On iOS most
system code lives in the dyld shared cache and has no usable runtime symbol
table, so module-relative offsets are what you actually paste into a
disassembler after extracting the image.

---

## Timeline

```text
00:00.021  FILESYSTEM  open("/private/var/mobile/...") -> 7
                       caller: MobileSafari + 0x1a83bc  tid 17

00:00.038  SECURITY    SecItemCopyMatching()
                       caller: Security + 0x4c210  tid 12
```

---

## Backtraces

An API call by itself is rarely enough to understand *why* it happened.

```text
SecItemCopyMatching()
        │
        ├── MobileSafari
        ├── SafariServices
        ├── Foundation
        └── libsystem_kernel
```

Use `Backtracer.ACCURATE`. It relies on frame pointer chains and generally works
on iOS system code. `FUZZY` scans the stack and returns plausible-looking noise —
do not reach for it because it "returns more frames."

---

## Known limitations

### One process at a time

This is the big one, and it is not a small fix.

On iOS an application is frequently a constellation of sandboxed processes.
Safari is seven:

| Process | Responsibility |
|---|---|
| `Safari` | UI, ObjC/Swift, `WKWebView` API calls |
| `com.apple.WebKit.WebContent` | Renderer. Tightest sandbox on the system |
| `com.apple.WebKit.Networking` | Sockets, TLS, cookies |
| `com.apple.WebKit.GPU` | Compositing, media |
| `com.apple.Safari.History` | History store |
| `com.apple.Safari.SearchHelper` | Search |
| `BrowserEngineKit.Intermediary` | Process brokering |

A `-[WKWebView loadRequest:]` call in `Safari`, the socket it eventually causes in
`WebKit.Networking`, and the file it touches somewhere else are three events in
three processes. A single-target attach cannot produce that timeline.

The `process` field in the event schema exists for this reason. Multi-attach is
Phase 3 work.

### Injection does not work everywhere

Foreground apps attach reliably. Background daemons currently fail with
`unexpected early end-of-stream` — the agent starts and the channel dies during
handshake. Under investigation; leading suspect is jetsam killing the target when
`frida-agent` pushes it past its memory limit.

Building an attachability map of the whole system (`--probe`) is a planned
feature, and a good way to derive the practical shape of the iOS security model
empirically.

### Swift is mostly invisible

Swift methods are statically dispatched and do not appear in the Objective-C
runtime unless marked `@objc dynamic`. An app written in modern Swift will look
almost silent through an ObjC-only lens.

---

## Engineering notes

Things that are non-obvious and cost real time to rediscover.

**Reentrancy.** Frida's own transport calls `write()`/`send()` inside the target.
Hooking those and logging from the hook recurses or deadlocks. The agent uses a
per-thread guard — per-thread, not global, because two threads may legitimately
be inside two different hooks at once.

**Throughput.** `send()` is a serialized round trip to the host. One call per
event makes a busy process crawl. Events are batched (128 events / 100 ms).

**libc symbol aliases.** `open` is frequently reached via `open$NOCANCEL`. Same
for `read`, `write`, `close`. Hook only the plain name and you will conclude the
process does no file I/O.

**16KB pages.** `pageSize` is 16384, not 4096. Every piece of page math —
`mmap` observation, permission changes, ASLR slide granularity, page-aligned
patching — depends on this.

**arm64e.** Frida reports `arch: "arm64"`, but pointer authentication is live.
Relevant to stack walking and to any pointer you store.

**`objc_msgSend` is not a hook point.** It is called millions of times per second
and hooking it globally will hang the process. Resolve a specific class, walk its
method list, attach to individual IMPs.

**Frida 17 moved the bridges out.** `ObjC`, `Swift`, and `Java` are no longer
globals in the core runtime; they ship as separate packages requiring
`frida-compile`. The agent avoids the dependency by resolving `objc_msgSend` and
`libswiftCore.dylib` directly. Module lookup also changed
(`Module.getExportByName(null, …)` → `Module.getGlobalExportByName`); the agent
routes all lookups through one compat shim.

**Reading pointers can fault.** A `char *` may be null, unmapped, or unmapped
between the call and your read. Always go through the safe reader.

---

## Roadmap

### Phase 1 — MVP

- [x] Frida connection
- [x] Process attachment
- [x] Process metadata
- [x] Module enumeration
- [x] Event normalization
- [x] JSON export
- [ ] Filesystem observation — `open` done; `close`, `read`, `write`, `stat` next
- [ ] Native backtraces
- [ ] Network observation
- [ ] Objective-C observation
- [ ] Security API observation
- [ ] Terminal timeline

Ordering is intentional. The event schema and JSON export come *before* the
hooks, so every subsystem is written as a producer into a fixed shape rather than
six ad-hoc print formats normalized afterwards. Backtraces come before
Objective-C because symbolication forces you to understand the shared cache and
ASLR slide, which everything downstream depends on.

### Phase 2

- [ ] `--probe` attachability map
- [ ] Recording / replay — capture once, develop the UI against a file
- [ ] Dynamic `dlopen` tracking
- [ ] Mach / XPC observation
- [ ] Symbol resolution against extracted shared cache images
- [ ] Event filtering and aggregation
- [ ] Interactive TUI

### Phase 3

- [ ] Multi-process attach and correlated timelines
- [ ] Web-based visualization
- [ ] Call graphs
- [ ] Process relationship graphs
- [ ] Investigation sessions

---

## What iOScope is not

- a debugger
- a disassembler
- a packet sniffer
- a complete malware analyzer
- a replacement for Frida
- an automatic vulnerability detector

It is an **observation and correlation layer**. It reports what happened. It does
not judge whether an operation is secure.

---

## Learning objectives

This project is deliberately structured so that implementing each subsystem
requires learning the underlying iOS mechanism first.

```text
iOS Process Model
        ↓
Mach-O
        ↓
dyld  +  shared cache
        ↓
Objective-C Runtime
        ↓
ARM64 / arm64e
        ↓
Frida internals
        ↓
Mach / XPC
        ↓
Security.framework
        ↓
Sandbox  ·  entitlements  ·  jetsam
        ↓
Runtime instrumentation
```

Coming from Android, the rough mapping:

| Android | iOS |
|---|---|
| APK | `.ipa` / `.app` bundle |
| DEX + ART | Mach-O ARM64, no bytecode VM |
| JNI `.so` (ELF) | `.dylib` / `.framework` (Mach-O) |
| `linker64` | `dyld` |
| Java reflection | Objective-C runtime |
| Zygote fork | `launchd` + `posix_spawn` |
| Binder | Mach ports / MIG / XPC |
| SELinux + per-app UID | Sandbox profiles + entitlements |
| Keystore | Keychain (`Security.framework`) |
| `logcat` | `log stream` / oslog |
| `/data/data/<pkg>` | `/var/mobile/Containers/Data/Application/<UUID>` |
| AndroidManifest.xml | `Info.plist` + entitlements |
| `/proc/<pid>/maps` | no `/proc` — `libproc`, `sysctl`, `task_for_pid` |

Three Android reflexes that will mislead you: there is no `/proc`; system
libraries are merged into the dyld shared cache and do not exist as files on
disk; and one app is not one process.

---

## License

TBD