/*
 * iOScope agent — filesystem observation
 *
 * This runs INSIDE the target iOS process. Everything here is subject to
 * three constraints that shape the whole design:
 *
 *   1. Reentrancy. Frida's own transport calls write()/send() inside the
 *      target. If you hook those and log from the hook, you deadlock or
 *      recurse forever. Hence guard().
 *   2. Throughput. send() is a serialized round trip to the host. One call
 *      per event will make a busy process crawl. Hence the batching queue.
 *   3. Symbol resolution is expensive. Never resolve inside a hot hook
 *      unless you asked for it.
 *
 * Findings from this target, derived by disassembly rather than assumed:
 *   - open/open$NOCANCEL are wrappers (they normalise the variadic mode
 *     argument); __open/__open_nocancel are the raw syscall stubs they
 *     chain into. Hook the wrappers — their returnAddress is the real caller.
 *   - close and read have NO wrapper. The public symbol is the syscall stub,
 *     because their signatures are fixed and there is nothing to normalise.
 *   - close$NOCANCEL and __close_nocancel are the same address.
 *   - Darwin syscall numbers seen in x16: open 5, close 6,
 *     open_nocancel 0x18e, close_nocancel 0x18f.
 */

"use strict";

const T0 = Date.now();
const K = "libsystem_kernel.dylib";

/* ------------------------------------------------------------------ */
/* Frida API compatibility                                             */
/* ------------------------------------------------------------------ */
/*
 * Frida 17 reshuffled module lookup (Module.getExportByName(null, ...) is
 * on its way out in favour of Module.getGlobalExportByName). Rather than
 * pin a version, resolve through one shim so the rest of the file is
 * stable. If a lookup here starts returning null after a Frida upgrade,
 * this is the function to fix.
 */
function resolveExport(name, moduleName) {
  try {
    if (moduleName) {
      const m = Process.findModuleByName(moduleName);
      return m ? m.findExportByName(name) : null;
    }
    if (typeof Module.getGlobalExportByName === "function") {
      return Module.getGlobalExportByName(name);
    }
    return Module.findExportByName(null, name);
  } catch (e) {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Reentrancy guard                                                    */
/* ------------------------------------------------------------------ */
/*
 * Per-thread, not global: two threads may legitimately be inside two
 * different hooks at the same time. A global flag would silently drop
 * those events and you would spend an evening wondering why.
 */
const busy = new Set();

function guard(fn) {
  const tid = Process.getCurrentThreadId();
  if (busy.has(tid)) return;
  busy.add(tid);
  try {
    fn();
  } catch (e) {
    // Never let a hook throw into the target.
    send({ kind: "agent-error", message: String(e), stack: e.stack });
  } finally {
    busy.delete(tid);
  }
}

/* ------------------------------------------------------------------ */
/* Argument readers                                                    */
/* ------------------------------------------------------------------ */
/*
 * Reading a char* from a hooked process can fault: the pointer may be
 * null, unmapped, or pointing at a page that has been unmapped between
 * the call and your read. Always go through these.
 *
 * Raw vs quoted is a real distinction. Raw goes in the fd table; quoted
 * goes in the event stream. Mixing them gives you double-quoted paths.
 */
function readCStrRaw(p) {
  if (p.isNull()) return null;
  try {
    return p.readUtf8String();
  } catch (e) {
    return null;
  }
}

function quote(s) {
  return s === null || s === undefined ? "(null)" : JSON.stringify(s);
}

function readCStr(p) {
  return quote(readCStrRaw(p));
}

/* ------------------------------------------------------------------ */
/* fd -> path                                                          */
/* ------------------------------------------------------------------ */
/*
 * Populated by the open family, consulted by read/write, evicted by the
 * close family. Eviction is NOT optional: fd numbers are recycled
 * constantly, and because misses are cached too, a stale entry outlives
 * the file it described.
 *
 * fcntl(F_GETPATH) is the fallback for fds that predate our attach.
 * fcntl is VARIADIC — on Apple ARM64 variadic arguments are passed on the
 * stack, not in registers, so the '...' marker is load-bearing. Without
 * it fcntl reads garbage off the stack and returns -1 every time.
 */
const fdTable = new Map();

const F_GETPATH = 50;
const PATH_MAX = 1024;
let _fcntl = null;

function fcntlPath(fd) {
  if (_fcntl === null) {
    const a = resolveExport("fcntl", K) || resolveExport("fcntl", null);
    if (a === null) return null;
    _fcntl = new NativeFunction(a, "int", ["int", "int", "...", "pointer"]);
  }
  const buf = Memory.alloc(PATH_MAX); // per call: a shared buffer races
  try {
    if (_fcntl(fd, F_GETPATH, buf) === 0) return buf.readUtf8String();
  } catch (e) {}
  return null;
}

function fdPath(fd) {
  if (fd < 0) return null;
  if (fdTable.has(fd)) return fdTable.get(fd); // may be null: a cached miss
  const p = fcntlPath(fd);
  fdTable.set(fd, p); // cache misses too, or every socket read re-calls fcntl
  return p;
}

function fdRemember(fd, path) {
  if (fd >= 0 && path) fdTable.set(fd, path);
}

function fdForget(fd) {
  if (fd >= 0) fdTable.delete(fd);
}

/*
 * A null path is information, not a failure — it usually means a socket or
 * a pipe, which is an fd with no name in the filesystem. Say so rather than
 * rendering it as "None".
 */
function fdLabel(fd) {
  const p = fdPath(fd);
  return p === null ? "<unnamed fd>" : JSON.stringify(p);
}

/* ------------------------------------------------------------------ */
/* Event queue                                                         */
/* ------------------------------------------------------------------ */
const BATCH_SIZE = 128;
const FLUSH_MS = 100;

let queue = [];
let flushTimer = null;
let config = { backtrace: false, categories: null, objcFilter: null };

function flush() {
  flushTimer = null;
  if (queue.length === 0) return;
  const events = queue;
  queue = [];
  send({ kind: "events", events: events });
}

function emit(ev) {
  if (config.categories && config.categories.indexOf(ev.category) === -1)
    return;
  ev.t = Date.now() - T0;
  ev.thread = Process.getCurrentThreadId();
  queue.push(ev);
  if (queue.length >= BATCH_SIZE) {
    flush();
  } else if (flushTimer === null) {
    flushTimer = setTimeout(flush, FLUSH_MS);
  }
}

/* ------------------------------------------------------------------ */
/* Address -> human                                                    */
/* ------------------------------------------------------------------ */
/*
 * On iOS the answer to "where am I" is almost always module + offset,
 * because most system code lives in the dyld shared cache and has no
 * usable symbol table at runtime. Offsets are what you paste into a
 * disassembler after extracting the image.
 *
 * strip() first: on arm64e returnAddress is a signed pointer, and an
 * unstripped lookup silently fails to resolve.
 */
function describeAddress(addr) {
  const a = addr.strip();
  const m = Process.findModuleByAddress(a);
  if (m === null) return { raw: a.toString() };
  return {
    raw: a.toString(),
    module: m.name,
    offset: "0x" + a.sub(m.base).toString(16),
  };
}

function captureBacktrace(context) {
  if (!config.backtrace) return undefined;
  return Thread.backtrace(context, Backtracer.ACCURATE)
    .slice(0, 12)
    .map(describeAddress);
}

/* ------------------------------------------------------------------ */
/* Hook installation                                                   */
/* ------------------------------------------------------------------ */
/*
 * Three things this has to get right, all learned the hard way:
 *
 *   1. PAC. findExportByName returns a signed pointer on arm64e. Compare
 *      stripped addresses or you cannot tell aliases from distinct
 *      functions.
 *   2. Aliases. Some symbols are two names for one address
 *      (close$NOCANCEL == __close_nocancel). Hooking both emits two
 *      events per call, and nothing in the output looks wrong.
 *   3. Wrappers. Some symbols chain (open -> __open). Those have
 *      DIFFERENT addresses, so dedupe cannot catch them — you have to
 *      know not to list the inner one. Hook the outermost symbol: it is
 *      the one whose returnAddress points at the real caller.
 */
const installed = [];
const failed = [];
const aliased = [];

function hook(spec) {
  const names = spec.aliases ? [spec.name].concat(spec.aliases) : [spec.name];
  const claimed = new Map(); // stripped address -> name that got there first

  for (const name of names) {
    const addr = resolveExport(name, spec.module);
    if (addr === null) {
      failed.push(name + ": not found");
      continue;
    }

    const key = addr.strip().toString();
    if (claimed.has(key)) {
      aliased.push(name + " == " + claimed.get(key));
      continue;
    }
    claimed.set(key, name);

    try {
      Interceptor.attach(addr, {
        onEnter(args) {
          guard(() => {
            this.ev = {
              category: spec.category,
              symbol: spec.name, // canonical, so variants aggregate
              via: name, // but which one actually fired
              args: spec.onEnter ? spec.onEnter(args, this) : [],
              caller: describeAddress(this.returnAddress),
              backtrace: captureBacktrace(this.context),
            };
          });
        },
        onLeave(retval) {
          guard(() => {
            if (!this.ev) return; // onEnter was skipped by the guard
            if (spec.onLeave) this.ev.ret = spec.onLeave(retval, this);
            emit(this.ev);
            this.ev = null;
          });
        },
      });
      installed.push(name);
    } catch (e) {
      failed.push(name + ": " + e.message);
    }
  }

  if (claimed.size === 0) failed.push(spec.name + ": no symbol resolved");
}

/* ------------------------------------------------------------------ */
/* THE HOOKS                                                           */
/* ------------------------------------------------------------------ */
/*
 * Before adding anything here, run rpc.exports.dis on the symbol and its
 * variants. Do not assume the shape — open has a wrapper, close and read
 * do not, and that difference decides which symbol you hook.
 */
const SPECS = [
  /* -------- opening -------- */
  {
    category: "filesystem",
    module: K,
    name: "open",
    aliases: ["open$NOCANCEL"], // NOT __open — that is the inner stub
    onEnter: (args, inv) => {
      inv.path = readCStrRaw(args[0]);
      // args[2] is NOT mode: open is variadic, so mode is on the stack.
      return [quote(inv.path), "0x" + args[1].toInt32().toString(16)];
    },
    onLeave: (rv, inv) => {
      const fd = rv.toInt32();
      fdRemember(fd, inv.path);
      return fd;
    },
  },
  {
    category: "filesystem",
    module: K,
    name: "openat",
    aliases: ["openat$NOCANCEL"],
    onEnter: (args, inv) => {
      inv.path = readCStrRaw(args[1]); // args[0] is dirfd, not the path
      return [
        args[0].toInt32(),
        quote(inv.path),
        "0x" + args[2].toInt32().toString(16),
      ];
    },
    onLeave: (rv, inv) => {
      const fd = rv.toInt32();
      fdRemember(fd, inv.path);
      return fd;
    },
  },
  {
    category: "filesystem",
    module: K,
    name: "guarded_open_np",
    // SQLite and the system database layer use this. Miss it and you
    // wrongly conclude the process barely touches storage.
    onEnter: (args, inv) => {
      inv.path = readCStrRaw(args[0]);
      return [quote(inv.path)];
    },
    onLeave: (rv, inv) => {
      const fd = rv.toInt32();
      fdRemember(fd, inv.path);
      return fd;
    },
  },
  {
    category: "filesystem",
    module: K,
    name: "open_dprotected_np",
    // args[2] is the Data Protection class (1-4 = A-D). The most
    // security-relevant integer in the whole filesystem set, and it
    // appears nowhere else.
    onEnter: (args, inv) => {
      inv.path = readCStrRaw(args[0]);
      return [
        quote(inv.path),
        "0x" + args[1].toInt32().toString(16),
        "class=" + args[2].toInt32(),
      ];
    },
    onLeave: (rv, inv) => {
      const fd = rv.toInt32();
      fdRemember(fd, inv.path);
      return fd;
    },
  },

  /* -------- closing -------- */
  {
    category: "filesystem",
    module: K,
    name: "close",
    aliases: ["close$NOCANCEL", "__close_nocancel"], // third dedupes by address
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd)];
    },
    onLeave: (rv, inv) => {
      const r = rv.toInt32();
      if (r === 0) fdForget(inv.fd); // only evict on success
      return r;
    },
  },
  {
    category: "filesystem",
    module: K,
    name: "guarded_close_np",
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd)];
    },
    onLeave: (rv, inv) => {
      const r = rv.toInt32();
      if (r === 0) fdForget(inv.fd);
      return r;
    },
  },

  /* -------- reading -------- */
  /*
   * NEVER touch args[1] in this group. It is the destination buffer:
   * uninitialised at onEnter, and full of file contents at onLeave.
   * Log the count. The return value is bytes ACTUALLY read, which is
   * often less than requested, and 0 means EOF.
   */
  {
    category: "filesystem",
    module: K,
    name: "read",
    aliases: ["read$NOCANCEL", "__read_nocancel"],
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd), "want=" + args[2].toInt32()];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "pread",
    aliases: ["pread$NOCANCEL", "__pread_nocancel"],
    // Positional read. SQLite leans on this heavily.
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [
        inv.fd,
        fdLabel(inv.fd),
        "want=" + args[2].toInt32(),
        "off=" + args[3].toInt32(),
      ];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "readv",
    aliases: ["readv$NOCANCEL", "__readv_nocancel"],
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd), "iovcnt=" + args[2].toInt32()];
    },
    onLeave: (rv) => rv.toInt32(),
  },

  /* -------- symlinks -------- */
  {
    category: "filesystem",
    module: K,
    name: "readlink",
    // readlinkat is NOT an alias: it takes (dirfd, path, buf, size), so
    // args[0] is an int. Same shape of mistake as openat vs open.
    onEnter: (args) => [readCStr(args[0])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "readlinkat",
    onEnter: (args) => [args[0].toInt32(), readCStr(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },

  // TODO write / pwrite / writev / guarded_write_np / guarded_pwrite_np
  //      Run dis on each first. write has no wrapper (fixed signature),
  //      so expect the close/read shape, not the open shape.
  // TODO stat / lstat / fstat / fstatat  (+ the 64 variants)
  // TODO getattrlist / getattrlistat / getattrlistbulk / fgetattrlist
  //      NSFileManager uses these instead of stat. Hook stat only and
  //      directory and metadata work looks invisible.
  // TODO unlink / rename / renamex_np / mkdir / truncate / fsync
  // TODO clonefile / copyfile — APFS copies files with no read/write at all
  // TODO mmap — a file-backed mapping is read through page faults, so a
  //      process can consume an entire file with zero read() events
  // TODO socket / connect / send / recv. connect() takes struct sockaddr*:
  //      on Darwin sa_len is the FIRST byte, so sa_family is at offset 1,
  //      and AF_INET6 is 30, not 10.
  // TODO SecItemCopyMatching / SecItemAdd (module 'Security'). Arguments
  //      are CFDictionaryRef — use CFCopyDescription, and CFRelease what
  //      it hands back.
];

/* ------------------------------------------------------------------ */
/* Objective-C observation                                             */
/* ------------------------------------------------------------------ */
/*
 * Deliberately left empty.
 *
 * Do NOT reach for objc_msgSend. It is called millions of times per
 * second and hooking it globally will hang the process. Resolve a
 * specific class, walk its method list, attach to individual IMPs.
 */
function objcAvailable() {
  return resolveExport("objc_msgSend", null) !== null;
}

function swiftAvailable() {
  return Process.findModuleByName("libswiftCore.dylib") !== null;
}

function installObjC(filter) {
  // NB: not `ObjC.available` — there is no ObjC global in Frida 17.
  if (!objcAvailable()) {
    send({ kind: "agent-error", message: "ObjC runtime not available" });
    return;
  }
  // TODO: new ApiResolver('objc').enumerateMatches('-[' + filter + ' *]')
  //       for the cheap path, or drive class_copyMethodList directly for
  //       the path that actually teaches the runtime.
}

/* ------------------------------------------------------------------ */
/* RPC surface                                                         */
/* ------------------------------------------------------------------ */
rpc.exports = {
  meta() {
    return {
      pid: Process.id,
      arch: Process.arch, // 'arm64' even on arm64e — PAC is still live
      platform: Process.platform,
      pointerSize: Process.pointerSize,
      pageSize: Process.pageSize, // 16384 here, not 4096
      objcAvailable: objcAvailable(),
      swiftAvailable: swiftAvailable(),
      threads: Process.enumerateThreads().length,
      fridaVersion: Frida.version,
    };
  },

  modules() {
    return Process.enumerateModules().map((m) => ({
      name: m.name,
      base: m.base.toString(),
      size: m.size,
      path: m.path,
    }));
  },

  ranges() {
    // Closest thing iOS has to /proc/<pid>/maps.
    return Process.enumerateRanges("r--").map((r) => ({
      base: r.base.toString(),
      size: r.size,
      protection: r.protection,
      file: r.file ? r.file.path : null,
    }));
  },

  start(cfg) {
    config = Object.assign(config, cfg || {});
    for (const spec of SPECS) hook(spec);
    if (config.objcFilter) installObjC(config.objcFilter);
    return { installed, failed, aliased };
  },

  drain() {
    flush();
  },

  /* ---- introspection helpers ---- */

  // What does this image actually export? Your libSystem is the authority,
  // not anybody's list.
  survey(needles, moduleNames) {
    const mods = moduleNames || [K, "libsystem_c.dylib"];
    const out = {};
    for (const name of mods) {
      const m = Process.findModuleByName(name);
      if (m === null) {
        out[name] = "not loaded";
        continue;
      }
      out[name] = m
        .enumerateExports()
        .filter((e) => e.type === "function")
        .map((e) => e.name)
        .filter((n) => needles.some((p) => n.indexOf(p) !== -1))
        .sort();
    }
    return out;
  },

  // Stripped addresses, so you can tell aliases from distinct functions.
  addrs(names, moduleName) {
    const m = Process.findModuleByName(moduleName || K);
    const out = {};
    names.forEach((n) => {
      const a = m ? m.findExportByName(n) : null;
      out[n] = a === null ? null : a.strip().toString(); // null-safe
    });
    return out;
  },

  // Read the stub. 'mov x16, #N' + 'svc #0x80' is a raw syscall (N is the
  // syscall number); a stack frame prologue means it is a wrapper that
  // chains somewhere else.
  dis(names, count, moduleName) {
    const m = Process.findModuleByName(moduleName || K);
    const limit = count || 8;
    const out = {};
    names.forEach((n) => {
      const a = m ? m.findExportByName(n) : null;
      if (a === null) {
        out[n] = null;
        return;
      }
      const p = a.strip();
      const lines = [];
      let cur = p;
      try {
        for (let i = 0; i < limit; i++) {
          const insn = Instruction.parse(cur);
          lines.push(
            insn.address.sub(p) + ": " + insn.mnemonic + " " + insn.opStr
          );
          if (/^(ret|retab|b|br|braa|brab)$/.test(insn.mnemonic)) break;
          cur = insn.next;
        }
      } catch (e) {
        lines.push("<parse error: " + e.message + ">");
      }
      out[n] = lines;
    });
    return out;
  },

  // Current fd -> path mapping. If read events show <unnamed fd> for a
  // file you know was opened, look here first.
  fdtable() {
    const out = {};
    fdTable.forEach((v, k) => {
      out[k] = v;
    });
    return out;
  },

  // Proof that fcntl needs the '...' marker. Apple ARM64 passes variadic
  // arguments on the stack, so the three-register declaration reads
  // garbage and returns -1.
  testfd(fd) {
    const a = resolveExport("fcntl", K);
    if (a === null) return { error: "fcntl not found" };
    const bad = new NativeFunction(a, "int", ["int", "int", "pointer"]);
    const good = new NativeFunction(a, "int", ["int", "int", "...", "pointer"]);
    const b1 = Memory.alloc(PATH_MAX);
    const b2 = Memory.alloc(PATH_MAX);
    return {
      without_varargs: { rv: bad(fd, F_GETPATH, b1), path: b1.readUtf8String() },
      with_varargs: { rv: good(fd, F_GETPATH, b2), path: b2.readUtf8String() },
    };
  },
};