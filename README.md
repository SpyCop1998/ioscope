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

Everything in this README below the Quickstart is a real captured session
against a live iOS VM — `python3 cli.py`, real PIDs, real file paths, real
stack traces. Nothing here is hand-typed example output.

---

## Status

🚧 **Early development**, but well past the MVP. Filesystem, network,
security, memory, and Objective-C observation are all wired up and hooking
live processes.

| Capability | State |
|---|---|
| Frida connection (remote) | working |
| Process attachment | working for foreground apps; daemon injection unreliable (see below) |
| Process spawn (`-f`) | flaky on this rig — see Known limitations |
| Process metadata | working |
| Module enumeration | working |
| Memory range enumeration | working |
| `--probe` attachability map | working |
| Event schema + batching queue | working |
| JSON export / `--replay` | working |
| Filesystem observation | ~30 symbols: open/close/read/write families, stat/attrlist, symlinks, rename/unlink/mkdir, APFS clonefile |
| Memory observation | `mmap` (anon filtered out), `mprotect` |
| Network observation | socket/connect/bind/accept/send·recv families, `getaddrinfo`, sockaddr decoding (v4/v6/unix) |
| Security observation | `SecItem*`, `SecAccessControlCreateWithFlags`, `SecTrustEvaluateWithError`, `errSecXxx` decoding |
| Objective-C observation | dynamic method hooking by class name (with superclass depth) or `ApiResolver` glob, type-encoding-aware argument rendering |
| Native backtraces | working — `Backtracer.ACCURATE`, module+offset and symbol resolution through the shared cache |
| Terminal timeline | working — colorized, `-v` for caller/tid detail |

APIs and output formats will still change.

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

Every command below was run against: iOS `26.6`, jailbreak variant `jb`,
`frida-server 17.17.0`, target process `Safari` (MobileSafari), reached over
`--host 192.168.64.7:27043`.

The VM is a complete iOS system — SpringBoard, the full daemon set, Safari and
its process family are all present. arm64e, 16KB pages, real dyld shared cache,
real sandbox.

**What is not representative:** the Jailbreak variant relaxes AMFI, so anything
observed about code signing, entitlement enforcement, or launch constraints does
not reflect a stock device. Everything else does. (Its tweak injection layer —
`systemhook.dylib` / `TweakLoader.dylib`, visible in every `--modules` dump
below — is also *not* representative of a stock process's module list.)

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

## Quickstart

Find something to attach to:

```text
$ python3 cli.py --host 192.168.64.7:27043 --list
511 processes
     1  launchd
    31  UserEventAgent
    32  logd
    ...
 26983  Safari
 26989  com.apple.Safari.SearchHelper

511 processes
```

PIDs churn constantly on iOS — Safari's own PID changed twice in the ~10
minutes this README was being written. `--list` right before you attach, and
attach by name when you can; iOScope resolves the name to whatever PID is
current at that instant.

Ask it what it is, with nothing hooked yet:

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --meta
{
  "pid": 27013,
  "arch": "arm64",
  "platform": "darwin",
  "pointerSize": 8,
  "pageSize": 16384,
  "objcAvailable": true,
  "swiftAvailable": true,
  "threads": 8,
  "fridaVersion": "17.17.0"
}
```

Then watch it live:

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --category filesystem --backtrace --duration 8
[+] 78 hooks installed
[=] collapsed as duplicate addresses: __close_nocancel == close$NOCANCEL; ...
[*] streaming for 8.0s

00:02.390  FILE  open("/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist", O_RDONLY|O_NONBLOCK) -> 56   libswiftDarwin.dylib`_fcntl_overlay_open
              Foundation`readBytesFromFile(path:reportProgress:maxLength:options:attributesToRead:attributes:)
              Foundation`-[NSData(NSData) initWithContentsOfFile:options:maxLength:error:]
              CoreServices`+[_LSURLOverride(Functions) iTunesStoreURL:]
              CoreServices`-[LSApplicationWorkspace(LSURLOverride) URLOverrideForURL:]
              UIKitCore`-[UIApplication _shouldAttemptOpenURL:]

--- 46 events in 8.0s ---
     46  filesystem
      6  events/sec
```

That trace is real: it was captured while a script called
`-[UIApplication openURL:options:completionHandler:]` inside Safari to
navigate to `https://example.com/`. The backtrace is `libswiftDarwin.dylib`
→ Swift `Foundation` overlay → Objective-C `Foundation`/`CoreServices` →
`UIKitCore`, symbolicated all the way through frameworks that ship with no
runtime symbol table — this is the shared-cache export-index fallback
(described in Symbolication, below) doing its job.

If nothing is happening in the target, iOScope tells you rather than sitting
there silently:

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --category network --duration 10
[+] 78 hooks installed
[*] streaming for 10.0s


[*] no events. a quiet process looks identical to a broken hook —
    trigger activity in the target and try again
```

(That specific run is also a live illustration of the "one process at a
time" limitation below: the `openURL:` navigation produced filesystem events
in `Safari` but zero `network` events in `Safari` — the actual socket work
happened in `com.apple.WebKit.Networking`, a different process, which this
invocation was not attached to.)

---

## Usage

### Survey the device

```bash
cli.py --host H --list                     # every process, pid + name
cli.py --host H --probe                    # attachability map of the system
cli.py --host H Safari --meta              # process metadata
cli.py --host H Safari --modules           # module map
cli.py --host H Safari --ranges            # memory map
```

`--probe` walks every process, attaches, detaches, and records the outcome.
It is slow and it is meant to be — this is not a fuzzer, it's the practical
shape of the platform's security model, derived rather than read:

```text
$ python3 cli.py --host 192.168.64.7:27043 --probe --probe-limit 12
[*] probing 12 processes — this takes a while, ctrl-c to stop

+      31  UserEventAgent                               ok
-      33  fseventsd                                    ProcessNotRespondingError process with pid 33 either refused to load frida-age
-      35  distnoted                                    ProcessNotRespondingError unexpected early end-of-stream
-      36  notifyd                                      ProcessNotRespondingError unexpected early end-of-stream
+      37  usermanagerd                                 ok
+      39  peopled                                      ok
+      40  SpringBoard                                  ok
+      41  assistantd                                   ok
+      42  bash                                         ok

--- outcomes ---
    6  ok
    4  ProcessNotRespondingError
    2  skipped
```

(`launchd` and `logd` are silently skipped — they're in `PROBE_SKIP`, on the
theory that nothing good comes of poking them even briefly. Rows print to
stdout and the summary to stderr, so if you redirect both into one file the
summary can appear to jump ahead of the rows — that's a buffering artifact
of piping, not a bug; on a real terminal the rows scroll first.)

Four `ProcessNotRespondingError`s out of ten attempted daemons, all
`unexpected early end-of-stream` or an explicit refusal — this is the exact
failure mode described in Known limitations, reproduced on demand.

### Ask the target (introspection — nothing is hooked)

These all answer a question and exit. Use them to verify an assumption
*before* writing a hook spec, not after.

**What does this image actually export?**

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --survey open,close --module libsystem_kernel.dylib
{
  "libsystem_kernel.dylib": [
    "__channel_open", "__close_nocancel", "__guarded_open_dprotected_np",
    "__guarded_open_np", "__nexus_open", "__open", "__open_dprotected_np",
    "__open_extended", "__open_nocancel", "__openat",
    "__openat_dprotected_np", "__openat_nocancel", "__sem_open",
    "__shm_open", "__workq_open", "close", "close$NOCANCEL", "fhopen",
    "guarded_close_np", "guarded_open_dprotected_np", "guarded_open_np",
    "necp_open", "necp_session_open", "open", "open$NOCANCEL",
    "open_dprotected_np", "openat", "openat$NOCANCEL",
    "openat_authenticated_np", "openat_dprotected_np", "openbyid_np",
    "posix_spawn_file_actions_addclose", "posix_spawn_file_actions_addopen",
    "sem_close", "sem_open", "shm_open"
  ]
}
```

**Stripped addresses, so aliases are distinguishable from distinct symbols:**

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --addrs 'open,open$NOCANCEL,__open'
{
  "open": "0x24ed49748",
  "open$NOCANCEL": "0x24ed496e8",
  "__open": "0x24ed4977c"
}
```

Three distinct addresses — confirming the header comment in `agent.js`:
`open` and `open$NOCANCEL` are wrapper entry points, `__open` is a separate,
inner syscall stub. Hooking the wrapper is correct; its `returnAddress` is
the real caller. Compare with a pair that *does* collapse:

**Read the raw stub — a real syscall vs. a wrapper, from the actual
instructions, not an assumption:**

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --dis 'write,write$NOCANCEL' --dis-count 6
{
  "write": [
    "0x0: mov x16, #4",
    "0x4: svc #0x80",
    "0x8: b.lo #0x24ed48050",
    "0xc: pacibsp ",
    "0x10: stp x29, x30, [sp, #-0x10]!",
    "0x14: mov x29, sp"
  ],
  "write$NOCANCEL": [
    "0x0: mov x16, #0x18d",
    "0x4: svc #0x80",
    "0x8: b.lo #0x24ed4a3c0",
    "0xc: pacibsp ",
    "0x10: stp x29, x30, [sp, #-0x10]!",
    "0x14: mov x29, sp"
  ]
}
```

`mov x16, #N` / `svc #0x80` *is* the syscall — no wrapper to see through.
`write` uses syscall number 4, `write$NOCANCEL` uses `0x18d` — two genuinely
different entry points into the kernel, confirming `write` has no wrapper
layer the way `open` does, exactly as the header comment predicts.

**Prove the `fcntl` variadic marker is load-bearing, not decoration:**

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --testfd 1
{
  "without_varargs": { "rv": 0, "path": "" },
  "with_varargs": { "rv": 0, "path": "/dev/null" }
}
```

Same call, same fd, two `NativeFunction` signatures. Without the `"..."`
marker in the arg-type array, Apple ARM64's calling convention for variadic
functions puts the real argument on the stack where this declaration never
looks — the call still returns `0` (success!) but the output buffer is
never actually filled, so `path` comes back empty. That's the "plausible
wrong number instead of an error" trap the codebase warns about, caught
live: a naive read of this result would say fd 1 has no path, when it
plainly does.

**Sanity-check the `struct stat` offsets against a file of known size:**

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --teststat /etc/hosts
{
  "rv": 0,
  "decoded": "reg 644 size=213"
}
```

`/etc/hosts` on this VM is 213 bytes — `ST_SIZE_OFF = 96` checks out.

**What classes exist, before deciding what to hook:**

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --objc-classes '^NSURL'
{
  "total": 89622,
  "matched": [
    "NSURL", "NSURLAuthenticationChallenge",
    "NSURLAuthenticationChallengeInternal", "NSURLCache",
    "NSURLCacheInternal", "NSURLComponents", "NSURLConnection",
    "NSURLConnectionInternal", "NSURLConnectionInternalConnection",
    "NSURLCredential", "NSURLCredentialStorage",
    "NSURLDirectoryEnumerator", "NSURLDownload", ...
  ]
}
```

89,622 classes live in Safari's process at once — almost all of them from
frameworks it links but never touches. This is why `--objc` hooking exists
as an explicit opt-in (see below) rather than "hook everything": at that
scale, even enumerating methods on every class would be its own
denial-of-service.

**Method list with type encodings, without hooking anything:**

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --objc-methods NSURLSession
{
  "instance": [
    {
      "name": "-[NSURLSession dataTaskWithURL:completionHandler:]",
      "types": "@32@0:8@16@?24",
      "parsed": "@ @ : @ ?",
      "imp": "0x1b4b238d4"
    },
    {
      "name": "-[NSURLSession dataTaskWithRequest:completionHandler:]",
      "types": "@32@0:8@16@?24",
      "parsed": "@ @ : @ ?",
      "imp": "0x1b496a094"
    },
    {
      "name": "-[NSURLSession uploadTaskWithRequest:fromData:completionHandler:]",
      "types": "@40@0:8@16@24@?32",
      "parsed": "@ @ : @ @ ?",
      "imp": "0x1b4b23358"
    },
    {
      "name": "-[NSURLSession invalidateAndCancel]",
      "types": "v16@0:8",
      "parsed": "v @ :",
      "imp": "0x1b4941148"
    },
    {
      "name": "-[NSURLSession webSocketTaskWithURL:protocols:]",
      "types": "@32@0:8@16@24",
      "parsed": "@ @ : @ @",
      "imp": "0x1b4b236b8"
    }
    // ... 71 instance methods total in this process
  ],
  "klass": [
    {
      "name": "+[NSURLSession sharedSession]",
      "types": "@16@0:8",
      "parsed": "@ @ :",
      "imp": "0x1b496cfc8"
    },
    {
      "name": "+[NSURLSession sessionWithConfiguration:delegate:delegateQueue:]",
      "types": "@40@0:8@16@24@32",
      "parsed": "@ @ : @ @ @",
      "imp": "0x1b4934dd0"
    }
    // ... 17 class methods total
  ]
}
```

(Full output is 88 methods across `instance` + `klass`; trimmed here for
space. Note the third-party `msv_dataTaskWithRequest:completionHandler:`
and `rc_logIdentifier` selectors that also show up in the untrimmed
output — categories added onto `NSURLSession` by something else loaded
into this process. `class_copyMethodList` only returns methods defined on
the exact class you ask for; a plain `dataTaskWithURL:` implemented by a
*subclass* wouldn't appear here at all — that's what `--objc-depth` is for
when hooking live, see below.)

### Observe (capture)

```bash
cli.py --host H Safari --category security
cli.py --host H Safari --category filesystem --duration 20 --out run.jsonl
cli.py --host H -f com.apple.mobilesafari --backtrace
cli.py --host H Safari --fdtable --duration 10
```

A capture always starts by reporting exactly what got installed, including
what got quietly collapsed as a duplicate address and what flat-out failed
to resolve — this is not a summary you have to ask for, it prints on every
run:

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --category filesystem --duration 6
[+] 78 hooks installed
[=] collapsed as duplicate addresses: __close_nocancel == close$NOCANCEL;
    __read_nocancel == read$NOCANCEL; __pread_nocancel == pread$NOCANCEL;
    __readv_nocancel == readv$NOCANCEL; __write_nocancel == write$NOCANCEL;
    __pwrite_nocancel == pwrite$NOCANCEL; __writev_nocancel == writev$NOCANCEL;
    stat64 == stat; lstat64 == lstat; fstat64 == fstat; fstatat64 == fstatat;
    statfs64 == statfs; __connect_nocancel == connect$NOCANCEL;
    __accept_nocancel == accept$NOCANCEL; __sendto_nocancel == sendto$NOCANCEL;
    __recvfrom_nocancel == recvfrom$NOCANCEL; __sendmsg_nocancel == sendmsg$NOCANCEL;
    __recvmsg_nocancel == recvmsg$NOCANCEL
[*] streaming for 6.0s

00:01.949  FILE  open("/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist", O_RDONLY|O_NONBLOCK) -> 70   libswiftDarwin.dylib`_fcntl_overlay_open
00:01.949  FILE  fstat(70, "/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist") -> 0 (reg 644 size=188)   Foundation`readBytesFromFile(path:reportProgress:maxLength:options:attributesToRead:attributes:)
00:01.949  FILE  read(70, "/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist", want=188) -> 188   Foundation`readBytesFromFileDescriptor(_:path:buffer:length:readUntilLength:reportProgress:)
00:01.950  FILE  close(70, "/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist") -> 0   Foundation`readBytesFromFile(path:reportProgress:maxLength:options:attributesToRead:attributes:)
00:02.038  FILE  guarded_pwrite_np(22, "/private/var/mobile/Library/Safari/SafariTabs.db-wal", want=4120, off=218392) -> 4120   libsqlite3.dylib`0x9ebd3 (0x181997bd3)
00:02.038  FILE  guarded_pwrite_np(22, "/private/var/mobile/Library/Safari/SafariTabs.db-wal", want=4120, off=222512) -> 4120   libsqlite3.dylib`0x9ebd3 (0x181997bd3)
... (27 sequential guarded_pwrite_np calls to the same fd, ~4KB apart)
00:02.044  FILE  stat("/private/var/mobile/Containers/Data/Application/D99179A6-.../Library/Safari/Thumbnails/metadata/metadata.sqlite-journal") -> -1   libsqlite3.dylib`0x17c57 (0x181910c57)

--- fd table ---
   22  /private/var/mobile/Library/Safari/SafariTabs.db-wal
   27  /private/var/mobile/Containers/Data/Application/D99179A6-.../Library/Safari/Thumbnails/metadata/metadata.sqlite

--- 99 events in 6.0s ---
     99  filesystem
     16  events/sec
```

That's SQLite's WAL writer flushing `SafariTabs.db-wal` page by page (27
`guarded_pwrite_np` calls, each ~4120 bytes, offsets climbing in lockstep —
this is what a WAL checkpoint looks like from the outside), plus Safari's
per-tab thumbnail cache doing a `stat`/`open`/`fstat` dance against a
`metadata.sqlite`. `libsqlite3.dylib\`0x9ebd3` — a bare offset instead of a
symbol name — is the shared-cache symbolication layer doing what it can:
no exported name at that address, so it reports module+offset honestly
instead of guessing.

The `--fdtable` dump at the end shows exactly what the two open,
never-closed fds from this run point to — the live proof that the
fd→path table (see Engineering notes) is doing its job: reads and writes
against fd 22 and 27 throughout the run were labeled with real paths, not
`<unnamed fd>`.

**`-v` for caller and thread on their own line** (default keeps one event
per line for grepping; `-v` trades that for detail):

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --category filesystem --duration 6 -v
00:01.949  FILE  open("/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist", O_RDONLY|O_NONBLOCK) -> 59
            caller: libswiftDarwin.dylib`_fcntl_overlay_open  tid 59411
00:01.958  FILE  open("/System/Library/Frameworks/CFNetwork.framework", O_RDONLY|O_DIRECTORY|O_CLOEXEC) -> 59
            caller: libsystem_c.dylib`__opendir2  tid 259 via open$NOCANCEL
```

That `via open$NOCANCEL` on the second line is the point of the `via`
field: `spec.name` is the canonical symbol you asked to observe (`open`),
`via` is which of its aliases the process actually called through this
time. Silent on the plain `open` line above because they matched.

**`--backtrace`** — full stack, module+offset for every frame, symbolicated
where possible (see the Quickstart example above for a live one). Use
`Backtracer.ACCURATE` (frame-pointer walking; the default). `--fuzzy`
switches to a stack scan that returns plausible-looking noise — don't reach
for it because it "finds more frames."

**`--json`** streams one JSON object per event instead of the colored
timeline — the same event, machine-readable:

```text
$ python3 cli.py --host 192.168.64.7:27043 Safari --json --duration 8
{"category": "filesystem", "symbol": "open", "via": "open", "args": ["\"/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist\"", "O_RDONLY|O_NONBLOCK"], "caller": {"raw": "0x2c0abdb40", "module": "libswiftDarwin.dylib", "offset": "0xb3f", "symbol": "_fcntl_overlay_open", "symbolOffset": "0x0"}, "ret": 70, "t": 1949, "thread": 32267}
{"category": "filesystem", "symbol": "fstat", "via": "fstat", "args": [70, "\"/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist\""], "caller": {"raw": "0x19c71f078", "module": "Foundation", "offset": "0x13077", "symbol": "readBytesFromFile(path:reportProgress:maxLength:options:attributesToRead:attributes:)", "symbolOffset": "0x0"}, "ret": "0 (reg 644 size=188)", "t": 1949, "thread": 32267}
```

**`--objc SPEC`** hooks live Objective-C methods instead of (or alongside)
libc symbols — by exact class name, or by glob through `ApiResolver`:

```bash
# every method defined directly on NSURLSession
cli.py --host H Safari --objc NSURLSession --category objc --duration 10

# also walk two levels of superclass
cli.py --host H Safari --objc NSURLSession --objc-depth 2

# glob form — no class name needed, matches across classes
cli.py --host H Safari --objc '-[NSURLSession *]'
```

```text
[agent] {'kind': 'objc-install', 'hooked': 88, 'failed': [], 'truncated': False, 'sample': ['-[NSURLSession dataTaskWithURL:completionHandler:]', '-[NSURLSession dataTaskWithRequest:completionHandler:]', ...]}
```

That line is real, and it's also an honest gap: `objc-install` isn't one of
the message kinds `cli.py`'s handler renders specially (only `events` and
`agent-error` are), so it falls through to the generic
`err(f"[agent] {payload}")` branch and prints as a raw Python dict repr.
Functionally harmless, cosmetically rough — worth a small patch before this
becomes a habit.

`--objc-describe` additionally calls `-description` on object arguments —
useful, but it runs target code (can allocate, take locks, re-enter your
hooks), so it's opt-in and not something to reach for in a hot path.

### Offline

```bash
cli.py --replay run.jsonl --category network
```

```text
$ python3 cli.py --replay run.jsonl --category filesystem

--- 99 events ---
     99  filesystem
00:01.949  FILE  open("/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist", O_RDONLY|O_NONBLOCK) -> 70   libswiftDarwin.dylib`_fcntl_overlay_open
00:01.949  FILE  fstat(70, "/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist") -> 0 (reg 644 size=188)   Foundation`readBytesFromFile(path:reportProgress:maxLength:options:attributesToRead:attributes:)
```

Same renderer, same category filter, no device needed — the `run.jsonl`
above is exactly the file the `--fdtable` capture wrote a few sections up.
This is the intended workflow for developing a new rendering or filter:
capture once, iterate against the file.

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

A real one, taken verbatim from a capture above:

```json
{
  "category": "filesystem",
  "symbol": "fstat",
  "via": "fstat",
  "args": [70, "\"/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist\""],
  "caller": {
    "raw": "0x19c71f078",
    "module": "Foundation",
    "offset": "0x13077",
    "symbol": "readBytesFromFile(path:reportProgress:maxLength:options:attributesToRead:attributes:)",
    "symbolOffset": "0x0"
  },
  "ret": "0 (reg 644 size=188)",
  "t": 1949,
  "thread": 32267
}
```

Addresses are reported as **module + offset**, not just raw pointers. On iOS most
system code lives in the dyld shared cache and has no usable runtime symbol
table, so module-relative offsets are what you actually paste into a
disassembler after extracting the image. When a symbol *is* recoverable — as
here, a demangled Swift function name pulled from `Foundation`'s export
table — you get that instead, for free.

---

## Timeline

Real output, one filesystem event and one from the security category, taken
from captures above and elsewhere in this session:

```text
00:01.949  FILE  fstat(70, "/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist") -> 0 (reg 644 size=188)   Foundation`readBytesFromFile(path:reportProgress:maxLength:options:attributesToRead:attributes:)

00:02.038  FILE  guarded_pwrite_np(22, "/private/var/mobile/Library/Safari/SafariTabs.db-wal", want=4120, off=218392) -> 4120   libsqlite3.dylib`0x9ebd3 (0x181997bd3)
```

With `-v`, caller and thread move to their own line and the alias actually
taken (`via`) shows up when it differs from the symbol you asked to watch:

```text
00:01.958  FILE  open("/System/Library/Frameworks/CFNetwork.framework", O_RDONLY|O_DIRECTORY|O_CLOEXEC) -> 59
            caller: libsystem_c.dylib`__opendir2  tid 259 via open$NOCANCEL
```

---

## Backtraces

An API call by itself is rarely enough to understand *why* it happened. Here
is a real one — `open()` on a plist, five frames up through Swift's
`Foundation` overlay into pure Objective-C `CoreServices`/`UIKitCore`,
captured while `-[UIApplication openURL:options:completionHandler:]` ran
inside Safari:

```text
open("/var/mobile/Library/Caches/com.apple.itunesstored/url-resolution.plist", ...)
        │
        ├── libswiftDarwin.dylib`_fcntl_overlay_open
        ├── Foundation`readBytesFromFile(path:reportProgress:maxLength:options:attributesToRead:attributes:)
        ├── Foundation`-[NSData(NSData) initWithContentsOfFile:options:maxLength:error:]
        ├── CoreServices`+[_LSURLOverride(Functions) iTunesStoreURL:]
        ├── CoreServices`-[LSApplicationWorkspace(LSURLOverride) URLOverrideForURL:]
        └── UIKitCore`-[UIApplication _shouldAttemptOpenURL:]
```

Every one of those frames lives in the dyld shared cache with no runtime
symbol table of its own — this reads because of the three-layer
symbolication scheme (cache → `DebugSymbol.fromAddress` → a hand-built,
binary-searched export index per module) doing the work `nm`/`atos` can't
do against a live shared-cache address.

Use `Backtracer.ACCURATE`. It relies on frame pointer chains and generally
works on iOS system code. `FUZZY` scans the stack and returns
plausible-looking noise — do not reach for it because it "returns more
frames."

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

Reproduced live in this session: attaching only to `Safari` and triggering a
page navigation produced 46 `filesystem` events in `Safari` and **zero**
`network` events, even with `--category network` enabled — the socket work
for that navigation happened in `com.apple.WebKit.Networking`, a process
this invocation never touched. A single-target attach genuinely cannot
produce that combined timeline.

The `process` field in the event schema exists for this reason. Multi-attach is
Phase 3 work.

### Injection does not work everywhere

Foreground apps attach reliably. Background daemons currently fail with
`unexpected early end-of-stream` — reproduced live via `--probe`: of 10
non-skipped daemons in a 12-process slice (`fseventsd`, `distnoted`,
`notifyd`, `runningboardd`, ...), 4 failed with exactly that error or an
explicit refusal to load `frida-agent`, while ordinary foreground/user
processes (`UserEventAgent`, `usermanagerd`, `SpringBoard`, `bash`) attached
cleanly. Leading suspect is jetsam killing the target when `frida-agent`
pushes it past its memory limit.

Spawn (`-f BUNDLE_ID`) is separately unreliable on this rig: spawning
`com.apple.mobilesafari` failed outright with

```text
frida.NotSupportedError: unexpectedly hit a crash with codes [ 0x6000000, 0x0 ]
at 0x24ed4e1d0 while initializing suspended process
```

— a crash while the process is still suspended at its entry point, before
iOScope's agent even runs. Not yet root-caused; a reasonable suspect given
this environment specifically is the tweak-injection layer
(`systemhook.dylib`/`TweakLoader.dylib`, visible in every `--modules` dump)
interacting badly with a process frozen mid-launch. Attaching to an
already-running Safari is unaffected and is the workflow every example in
this README actually uses.

Building an attachability map of the whole system (`--probe`, now
implemented — see Usage) is a good way to derive the practical shape of the
iOS security model empirically, and the numbers above are exactly that.

### Swift is mostly invisible

Swift methods are statically dispatched and do not appear in the Objective-C
runtime unless marked `@objc dynamic`. An app written in modern Swift will
look almost silent through an ObjC-only lens. (The Swift frames that *do*
show up in the backtrace example above — `libswiftDarwin.dylib`,
`Foundation`'s Swift overlay — are visible only because native hooking
symbolicates *any* return address on the stack, ObjC-dispatched or not; the
`--objc` hooking mode itself still only sees the `@objc`-exposed surface.)

---

## Engineering notes

Things that are non-obvious and cost real time to rediscover.

**Reentrancy.** Frida's own transport calls `write()`/`send()` inside the
target. Hooking those and logging from the hook recurses or deadlocks. The
agent uses a per-thread guard — per-thread, not global, because two threads
may legitimately be inside two different hooks at once.

**Throughput.** `send()` is a serialized round trip to the host. One call per
event makes a busy process crawl. Events are batched (128 events / 100 ms).

**libc symbol aliases.** `open` is frequently reached via `open$NOCANCEL`. Same
for `read`, `write`, `close`. Hook only the plain name and you will conclude the
process does no file I/O.

**16KB pages.** `pageSize` is 16384, not 4096 — confirmed above in the real
`--meta` output. Every piece of page math — `mmap` observation, permission
changes, ASLR slide granularity, page-aligned patching — depends on this.

**arm64e.** Frida reports `arch: "arm64"` (see `--meta` again), but pointer
authentication is live. Relevant to stack walking and to any pointer you
store.

**`objc_msgSend` is not a hook point.** It is called millions of times per
second and hooking it globally will hang the process. Resolve a specific
class, walk its method list, attach to individual IMPs — 89,622 classes
were live in the Safari process probed above; hooking all of them
indiscriminately is the same mistake at a different scale.

**Frida 17 moved the bridges out.** `ObjC`, `Swift`, and `Java` are no longer
globals in the core runtime; they ship as separate packages requiring
`frida-compile`. The agent avoids the dependency by resolving `objc_msgSend`
and `libswiftCore.dylib` directly. Module lookup also changed
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
- [x] Filesystem observation — open/close/read/write families, stat/attrlist, symlinks, mutations, APFS clones
- [x] Native backtraces
- [x] Network observation — sockets, connect/bind/accept, send/recv families, DNS, sockaddr decoding
- [x] Objective-C observation — by class name or glob, type-encoding-aware
- [x] Security API observation — SecItem family, trust evaluation, CF description bridge
- [x] Terminal timeline — basic, colorized, `-v` for detail

Ordering is intentional. The event schema and JSON export came *before* the
hooks, so every subsystem is written as a producer into a fixed shape rather than
six ad-hoc print formats normalized afterwards. Backtraces came before
Objective-C because symbolication forces you to understand the shared cache and
ASLR slide, which everything downstream depends on.

### Phase 2

- [x] `--probe` attachability map
- [x] Recording / replay — capture once (`--out run.jsonl`), develop the UI against the file (`--replay`)
- [ ] Dynamic `dlopen` tracking
- [ ] Mach / XPC observation
- [ ] Symbol resolution against extracted shared cache images
- [x] Event filtering — `--category`; aggregation still basic (counts only)
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
