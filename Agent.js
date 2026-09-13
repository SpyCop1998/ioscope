/*
 * iOScope agent — filesystem, memory, network, security observation
 *
 * This runs INSIDE the target iOS process. Three constraints shape it:
 *
 *   1. Reentrancy. Frida's transport calls write()/send() inside the
 *      target. Hook those and log from the hook and you recurse or
 *      deadlock. Hence guard(). This matters far more now that write is
 *      actually hooked.
 *   2. Throughput. send() is a serialized round trip. Hence batching.
 *   3. Cost per event. Symbol resolution, backtraces and struct reads all
 *      run on the target's threads. Anything optional sits behind a flag.
 *
 * Findings from this target, derived by disassembly rather than assumed:
 *   - open/open$NOCANCEL are wrappers that normalise the variadic mode
 *     argument; __open/__open_nocancel are the raw syscall stubs they
 *     chain into. Hook the wrappers: their returnAddress is the real caller.
 *   - close and read have NO wrapper. The public symbol IS the syscall
 *     stub, because their signatures are fixed.
 *   - close$NOCANCEL and __close_nocancel are one address.
 *   - Syscall numbers seen in x16: open 5, close 6, open_nocancel 0x18e,
 *     close_nocancel 0x18f.
 *
 * ANYTHING MARKED "VERIFY" IS A PREDICTION, NOT AN OBSERVATION.
 * Run rpc.exports.dis on it before trusting its output.
 */

"use strict";

const T0 = Date.now();
const K = "libsystem_kernel.dylib";
const CF = "CoreFoundation";
const SEC = "Security";

/* ================================================================== */
/* Frida API compatibility                                            */
/* ================================================================== */
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

function objcAvailable() {
  return resolveExport("objc_msgSend", null) !== null;
}

function swiftAvailable() {
  return Process.findModuleByName("libswiftCore.dylib") !== null;
}

/* ================================================================== */
/* Reentrancy guard                                                   */
/* ================================================================== */
/*
 * Per-thread, not global: two threads may legitimately be inside two
 * different hooks at once. A global flag silently drops those events.
 */
const busy = new Set();

function guard(fn) {
  const tid = Process.getCurrentThreadId();
  if (busy.has(tid)) return;
  busy.add(tid);
  try {
    fn();
  } catch (e) {
    send({ kind: "agent-error", message: String(e), stack: e.stack });
  } finally {
    busy.delete(tid);
  }
}

/* ================================================================== */
/* Safe readers                                                       */
/* ================================================================== */
/*
 * Any read can fault: a pointer may be null, unmapped, or unmapped
 * between the call and your read. Raw vs quoted is a real distinction —
 * raw goes in the fd table, quoted goes in the event stream.
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

function safe(fn, fallback) {
  try {
    const v = fn();
    return v === null || v === undefined ? fallback : v;
  } catch (e) {
    return fallback;
  }
}

function hex(n) {
  return "0x" + (n >>> 0).toString(16);
}

/* ================================================================== */
/* Flag decoders                                                      */
/* ================================================================== */
/*
 * Darwin values. Several differ from Linux — O_CREAT is 0x200 here, not
 * 0x40, and AF_INET6 is 30, not 10.
 */
const O_BITS = [
  [0x0004, "O_NONBLOCK"],
  [0x0008, "O_APPEND"],
  [0x0010, "O_SHLOCK"],
  [0x0020, "O_EXLOCK"],
  [0x0080, "O_FSYNC"],
  [0x0100, "O_NOFOLLOW"],
  [0x0200, "O_CREAT"],
  [0x0400, "O_TRUNC"],
  [0x0800, "O_EXCL"],
  [0x8000, "O_EVTONLY"],
  [0x100000, "O_DIRECTORY"],
  [0x200000, "O_SYMLINK"],
  [0x1000000, "O_CLOEXEC"],
];

function decodeOpenFlags(f) {
  const acc = ["O_RDONLY", "O_WRONLY", "O_RDWR"][f & 3] || "O_ACCMODE?";
  const out = [acc];
  for (const [bit, name] of O_BITS) if (f & bit) out.push(name);
  return out.join("|");
}

const PROT_BITS = [
  [1, "R"],
  [2, "W"],
  [4, "X"],
];

function decodeProt(p) {
  if (p === 0) return "---";
  return PROT_BITS.map(([b, n]) => (p & b ? n : "-")).join("");
}

const MAP_SHARED = 0x0001;
const MAP_PRIVATE = 0x0002;
const MAP_FIXED = 0x0010;
const MAP_JIT = 0x0800;
const MAP_ANON = 0x1000; /* Darwin value */

function decodeMapFlags(f) {
  const out = [];
  if (f & MAP_SHARED) out.push("SHARED");
  if (f & MAP_PRIVATE) out.push("PRIVATE");
  if (f & MAP_FIXED) out.push("FIXED");
  if (f & MAP_JIT) out.push("JIT");
  if (f & MAP_ANON) out.push("ANON");
  return out.length ? out.join("|") : hex(f);
}

/* ================================================================== */
/* Symbolication                                                      */
/* ================================================================== */
/*
 * Three layers, cheapest first:
 *   1. cache — the same addresses recur constantly
 *   2. DebugSymbol.fromAddress — works for the app's own binary,
 *      usually returns nothing for shared-cache code
 *   3. a sorted symbol index per module, binary-searched for the
 *      nearest preceding symbol
 *
 * Layer 3 is what makes shared-cache frames readable. Export tries
 * survive in the cache even though full symbol tables do not, so
 * enumerateExports() gives real names for most system functions.
 */
const symIndex = new Map();   // module name -> sorted [{a, n}]
const symCache = new Map();   // address string -> description object

/* A symbol more than this far from the address is almost certainly not
   the containing function — a gap in the index, not a real match. */
const MAX_SYM_OFFSET = 0x8000;

function buildIndex(m) {
  let idx = symIndex.get(m.name);
  if (idx !== undefined) return idx;

  const entries = [];
  const take = (list) => {
    for (const s of list) {
      if (s.type && s.type !== "function") continue;
      entries.push({ a: s.address.strip(), n: s.name });
    }
  };

  try { take(m.enumerateExports()); } catch (e) {}

  /* enumerateSymbols on a shared-cache module is slow and can be
     enormous. Opt-in only. */
  if (config.deepSymbols) {
    try { take(m.enumerateSymbols()); } catch (e) {}
  }

  entries.sort((x, y) => x.a.compare(y.a));
  symIndex.set(m.name, entries);
  return entries;
}

function nearestSymbol(idx, addr) {
  let lo = 0, hi = idx.length - 1, best = null;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (idx[mid].a.compare(addr) <= 0) { best = idx[mid]; lo = mid + 1; }
    else hi = mid - 1;
  }
  return best;
}

/*
 * isReturn: a backtrace frame holds the address AFTER the call
 * instruction. If the call was the last instruction of a function, that
 * address belongs to the NEXT function and you symbolicate the wrong
 * one. Look up addr-1 for return addresses; report the original.
 */
function describeAddress(addr, isReturn) {
  const a = addr.strip();
  const key = a.toString() + (isReturn ? "r" : "");
  const hit = symCache.get(key);
  if (hit !== undefined) return hit;

  const probe = isReturn ? a.sub(1) : a;
  const m = Process.findModuleByAddress(probe);
  const out = { raw: a.toString() };

  if (m === null) {
    symCache.set(key, out);
    return out;
  }

  out.module = m.name;
  out.offset = "0x" + probe.sub(m.base).toString(16);

  /* Layer 2 */
  try {
    const ds = DebugSymbol.fromAddress(probe);
    if (ds && ds.name) {
      out.symbol = ds.name;
      out.symbolOffset = "0x" + probe.sub(ds.address.strip()).toString(16);
      if (ds.fileName) { out.file = ds.fileName; out.line = ds.lineNumber; }
    }
  } catch (e) {}

  /* Layer 3 */
  if (!out.symbol) {
    const near = nearestSymbol(buildIndex(m), probe);
    if (near !== null) {
      const delta = probe.sub(near.a).toInt32();
      if (delta >= 0 && delta < MAX_SYM_OFFSET) {
        out.symbol = near.n;
        out.symbolOffset = "0x" + delta.toString(16);
      }
    }
  }

  symCache.set(key, out);
  return out;
}

function captureBacktrace(context) {
  if (!config.backtrace) return undefined;
  const mode = config.fuzzy ? Backtracer.FUZZY : Backtracer.ACCURATE;
  return Thread.backtrace(context, mode)
    .slice(0, config.btDepth || 12)
    .map((a) => describeAddress(a, true));
}

/* ================================================================== */
/* fd -> path                                                         */
/* ================================================================== */
/*
 * Populated by the open family, consulted by read/write, evicted by the
 * close family. Eviction is NOT optional: fd numbers are recycled
 * constantly, and because misses are cached too, a stale entry outlives
 * the file it described.
 *
 * fcntl(F_GETPATH) is the fallback for fds that predate our attach.
 * fcntl is VARIADIC — on Apple ARM64 variadic arguments go on the stack,
 * so the '...' marker is load-bearing. Without it fcntl reads garbage
 * and returns -1 every time. (Confirmed: rpc.exports.testfd.)
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
  const buf = Memory.alloc(PATH_MAX); /* per call: a shared buffer races */
  try {
    if (_fcntl(fd, F_GETPATH, buf) === 0) return buf.readUtf8String();
  } catch (e) {}
  return null;
}

function fdPath(fd) {
  if (fd < 0) return null;
  if (fdTable.has(fd)) return fdTable.get(fd); /* may be null: cached miss */
  const p = fcntlPath(fd);
  fdTable.set(fd, p); /* cache misses too, or every socket read re-calls */
  return p;
}

function fdRemember(fd, path) {
  if (fd >= 0 && path) fdTable.set(fd, path);
}

function fdForget(fd) {
  if (fd >= 0) fdTable.delete(fd);
}

/* A null path is information — usually a socket or pipe, an fd with no
   name in the filesystem. Say so rather than rendering it as "None". */
function fdLabel(fd) {
  const p = fdPath(fd);
  return p === null ? "<unnamed fd>" : JSON.stringify(p);
}

/* ================================================================== */
/* struct sockaddr                                                    */
/* ================================================================== */
/*
 * TWO Darwin differences that silently produce garbage if you carry
 * Linux assumptions across:
 *   1. sockaddr begins with a one-byte sa_len, so sa_family is at
 *      offset 1, NOT 0.
 *   2. AF_INET6 is 30 on Darwin, 10 on Linux.
 */
const AF_UNIX = 1;
const AF_INET = 2;
const AF_INET6 = 30;

function ntohs(v) {
  return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
}

function parseSockaddr(sa) {
  if (sa.isNull()) return "(null)";
  try {
    const family = sa.add(1).readU8();

    if (family === AF_INET) {
      const port = ntohs(sa.add(2).readU16());
      const b = new Uint8Array(sa.add(4).readByteArray(4));
      return b[0] + "." + b[1] + "." + b[2] + "." + b[3] + ":" + port;
    }

    if (family === AF_INET6) {
      const port = ntohs(sa.add(2).readU16());
      const b = new Uint8Array(sa.add(8).readByteArray(16));
      const parts = [];
      for (let i = 0; i < 16; i += 2)
        parts.push((((b[i] << 8) | b[i + 1]) >>> 0).toString(16));
      return "[" + parts.join(":") + "]:" + port;
    }

    if (family === AF_UNIX) {
      /* sun_path starts at offset 2, up to 104 bytes */
      return "unix:" + quote(readCStrRaw(sa.add(2)));
    }

    return "af(" + family + ")";
  } catch (e) {
    return "<unreadable sockaddr>";
  }
}

/* ================================================================== */
/* struct stat                                                        */
/* ================================================================== */
/*
 * VERIFY these offsets. This is the __DARWIN_64_BIT_INO_T layout, which
 * is the default on arm64, but reading at a wrong offset yields a
 * plausible-looking wrong number rather than an error — the worst kind
 * of bug. To check: stat a file whose size you know and confirm st_size.
 *
 *   st_mode  uint16 @ 4
 *   st_size  int64  @ 96
 */
const ST_MODE_OFF = 4;
const ST_SIZE_OFF = 96;

const S_IFMT = 0xf000;
const S_IFFILES = {
  0x1000: "fifo",
  0x2000: "chr",
  0x4000: "dir",
  0x6000: "blk",
  0x8000: "reg",
  0xa000: "lnk",
  0xc000: "sock",
};

function describeStatBuf(sb) {
  if (sb.isNull()) return null;
  try {
    const mode = sb.add(ST_MODE_OFF).readU16();
    const size = sb.add(ST_SIZE_OFF).readS64();
    const kind = S_IFFILES[mode & S_IFMT] || "?";
    const perm = (mode & 0o7777).toString(8);
    return kind + " " + perm + " size=" + size;
  } catch (e) {
    return null;
  }
}

/* ================================================================== */
/* struct attrlist                                                    */
/* ================================================================== */
/*
 * NSFileManager reaches for getattrlist rather than stat. Hook stat
 * alone and directory and metadata work looks invisible.
 *
 *   u_short   bitmapcount  @ 0    (ATTR_BIT_MAP_COUNT == 5)
 *   u_int16_t reserved     @ 2
 *   attrgroup_t commonattr @ 4
 *   attrgroup_t volattr    @ 8
 *   attrgroup_t dirattr    @ 12
 *   attrgroup_t fileattr   @ 16
 *   attrgroup_t forkattr   @ 20
 *
 * Rendering the bitmaps as hex is honest and sufficient; decoding every
 * ATTR_CMN_* bit is a project of its own.
 */
function describeAttrList(al) {
  if (al.isNull()) return "(null)";
  try {
    return (
      "common=" +
      hex(al.add(4).readU32()) +
      " vol=" +
      hex(al.add(8).readU32()) +
      " dir=" +
      hex(al.add(12).readU32()) +
      " file=" +
      hex(al.add(16).readU32())
    );
  } catch (e) {
    return "<unreadable attrlist>";
  }
}

/* ================================================================== */
/* CoreFoundation                                                     */
/* ================================================================== */
/*
 * Security.framework takes CFDictionaryRef arguments, which you cannot
 * read as strings. CFCopyDescription renders any CF object.
 *
 * OWNERSHIP IS REAL AND YOU ARE IN SOMEONE ELSE'S PROCESS. Anything from
 * a Create or Copy function is yours to CFRelease. Leak it and the target
 * grows until jetsam kills it — which will look like your hook being
 * unstable. Over-release and you crash immediately.
 */
const kCFStringEncodingUTF8 = 0x08000100;
const CF_DESC_MAX = 4096;

let _cf = null;

function cfInit() {
  if (_cf !== null) return _cf.ok;
  _cf = { ok: false };
  const copyDesc = resolveExport("CFCopyDescription", CF);
  const getCStr = resolveExport("CFStringGetCString", CF);
  const release = resolveExport("CFRelease", CF);
  if (!copyDesc || !getCStr || !release) return false;
  _cf.copyDescription = new NativeFunction(copyDesc, "pointer", ["pointer"]);
  _cf.getCString = new NativeFunction(getCStr, "bool", [
    "pointer",
    "pointer",
    "long",
    "uint32",
  ]);
  _cf.release = new NativeFunction(release, "void", ["pointer"]);
  _cf.ok = true;
  return true;
}

function cfDescribe(obj) {
  if (obj.isNull()) return "(null)";
  if (!cfInit()) return "<no CoreFoundation>";

  let desc = null;
  try {
    desc = _cf.copyDescription(obj);
    if (desc.isNull()) return "(no description)";
    const buf = Memory.alloc(CF_DESC_MAX);
    if (!_cf.getCString(desc, buf, CF_DESC_MAX, kCFStringEncodingUTF8))
      return "(undescribable)";
    const s = buf.readUtf8String();
    /* Descriptions of large dictionaries are enormous and full of
       newlines. Flatten and cap. */
    return s === null ? "(null)" : s.replace(/\s+/g, " ").slice(0, 600);
  } catch (e) {
    return "<cf error>";
  } finally {
    if (desc !== null && !desc.isNull()) {
      try {
        _cf.release(desc);
      } catch (e) {}
    }
  }
}

const ERR_SEC = {
  0: "errSecSuccess",
  "-50": "errSecParam",
  "-25291": "errSecNotAvailable",
  "-25293": "errSecAuthFailed",
  "-25299": "errSecDuplicateItem",
  "-25300": "errSecItemNotFound",
  "-25308": "errSecInteractionNotAllowed",
  "-26276": "errSecDecode",
  "-34018": "errSecMissingEntitlement",
};

function decodeSecStatus(n) {
  return ERR_SEC[String(n)] || String(n);
}

/* ================================================================== */
/* Event queue                                                        */
/* ================================================================== */
const BATCH_SIZE = 128;
const FLUSH_MS = 100;

let queue = [];
let flushTimer = null;
let config = {
  backtrace: false, btDepth: 12, fuzzy: false, deepSymbols: false,
  categories: null, objcFilter: null,
  objcMax: 400, objcDepth: 0, objcDescribe: false,
};
function wanted(category) {
  return !config.categories || config.categories.indexOf(category) !== -1;
}

function flush() {
  flushTimer = null;
  if (queue.length === 0) return;
  const events = queue;
  queue = [];
  send({ kind: "events", events: events });
}

function emit(ev) {
  ev.t = Date.now() - T0;
  ev.thread = Process.getCurrentThreadId();
  queue.push(ev);
  if (queue.length >= BATCH_SIZE) {
    flush();
  } else if (flushTimer === null) {
    flushTimer = setTimeout(flush, FLUSH_MS);
  }
}

/* ================================================================== */
/* Address -> human                                                   */
/* ================================================================== */
/*
 * On iOS "where am I" is almost always module + offset, because most
 * system code lives in the dyld shared cache with no usable runtime
 * symbol table. strip() first: on arm64e returnAddress is signed, and an
 * unstripped lookup silently fails to resolve.
 */


function captureBacktrace(context) {
  if (!config.backtrace) return undefined;
  return Thread.backtrace(context, Backtracer.ACCURATE)
    .slice(0, 12)
    .map(describeAddress);
}

/* ================================================================== */
/* Hook installation                                                  */
/* ================================================================== */
/*
 * Three things this must get right:
 *
 *   1. PAC. findExportByName returns a signed pointer on arm64e. Compare
 *      STRIPPED addresses or you cannot tell aliases from distinct
 *      functions.
 *   2. Aliases. Two names, one address (close$NOCANCEL ==
 *      __close_nocancel). Hook both and you emit two events per call,
 *      and nothing in the output looks wrong.
 *   3. Wrappers. Some symbols chain (open -> __open). Those have
 *      DIFFERENT addresses, so dedupe cannot catch them; you have to know
 *      not to list the inner one. Hook the outermost: its returnAddress
 *      is the real caller.
 */
const installed = [];
const failed = [];
const aliased = [];

function hook(spec) {
  const names = spec.aliases ? [spec.name].concat(spec.aliases) : [spec.name];
  const claimed = new Map();

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
            /* Filter before doing any work. With this many hooks
               installed, building an event you then discard is the
               dominant cost of a --category run. */
            if (!wanted(spec.category)) return;
            this.ev = {
              category: spec.category,
              symbol: spec.name,
              via: name,
              args: spec.onEnter ? spec.onEnter(args, this) : [],
              caller: describeAddress(this.returnAddress, true),
              backtrace: captureBacktrace(this.context),
            };
          });
        },
        onLeave(retval) {
          guard(() => {
            /* Bookkeeping that must happen even when filtered out,
               or the fd table desyncs. */
            if (spec.always) spec.always(retval, this);
            if (!this.ev) return;
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

/* ================================================================== */
/* SPECS                                                              */
/* ================================================================== */
/*
 * Before adding anything, run rpc.exports.dis on the symbol and its
 * variants. Do not assume the shape — open has a wrapper, close and read
 * do not, and that difference decides which symbol you hook.
 *
 * Volume warning: this is roughly sixty hooks. On a busy process, run
 * with --category rather than everything at once.
 */
const SPECS = [
  /* ---------------- opening ---------------- */
  {
    category: "filesystem",
    module: K,
    name: "open",
    aliases: ["open$NOCANCEL"] /* NOT __open — that is the inner stub */,
    onEnter: (args, inv) => {
      inv.path = readCStrRaw(args[0]);
      /* args[2] is NOT mode: open is variadic, mode is on the stack. */
      return [quote(inv.path), decodeOpenFlags(args[1].toInt32())];
    },
    always: (rv, inv) => fdRemember(rv.toInt32(), inv.path),
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "openat",
    aliases: ["openat$NOCANCEL"],
    onEnter: (args, inv) => {
      inv.path = readCStrRaw(args[1]); /* args[0] is dirfd */
      return [
        args[0].toInt32(),
        quote(inv.path),
        decodeOpenFlags(args[2].toInt32()),
      ];
    },
    always: (rv, inv) => fdRemember(rv.toInt32(), inv.path),
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "guarded_open_np",
    /* SQLite and the system database layer use this. Miss it and you
       wrongly conclude the process barely touches storage. */
    onEnter: (args, inv) => {
      inv.path = readCStrRaw(args[0]);
      return [quote(inv.path)];
    },
    always: (rv, inv) => fdRemember(rv.toInt32(), inv.path),
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "security",
    module: K,
    name: "open_dprotected_np",
    /* args[2] is the Data Protection class (1-4 = A-D). The most
       security-relevant integer in the filesystem set, and it appears
       nowhere else. Categorised as security for that reason. */
    onEnter: (args, inv) => {
      inv.path = readCStrRaw(args[0]);
      return [
        quote(inv.path),
        decodeOpenFlags(args[1].toInt32()),
        "class=" + args[2].toInt32(),
      ];
    },
    always: (rv, inv) => fdRemember(rv.toInt32(), inv.path),
    onLeave: (rv) => rv.toInt32(),
  },

  /* ---------------- closing ---------------- */
  {
    category: "filesystem",
    module: K,
    name: "close",
    aliases: ["close$NOCANCEL", "__close_nocancel"] /* third dedupes */,
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd)];
    },
    always: (rv, inv) => {
      if (rv.toInt32() === 0) fdForget(inv.fd); /* evict on success only */
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "guarded_close_np",
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd)];
    },
    always: (rv, inv) => {
      if (rv.toInt32() === 0) fdForget(inv.fd);
    },
    onLeave: (rv) => rv.toInt32(),
  },

  /* ---------------- reading ---------------- */
  /*
   * NEVER touch the buffer argument in this group. It is uninitialised
   * at onEnter and full of file contents at onLeave. Log the count.
   * The return value is bytes ACTUALLY read; 0 means EOF.
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
    /* Positional. SQLite leans on this heavily. */
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

  /* ---------------- writing ---------------- */
  /*
   * VERIFY: write is predicted to have the read/close shape (raw stub,
   * no wrapper) because its signature is fixed. Expected syscall numbers
   * write 4, write_nocancel 0x18d. Run dis before trusting.
   *
   * This is THE reentrancy hook. Frida's transport writes to a socket,
   * so without guard() the process hangs. If you want to see that
   * failure deliberately, snapshot the VM first.
   */
  {
    category: "filesystem",
    module: K,
    name: "write",
    aliases: ["write$NOCANCEL", "__write_nocancel"],
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd), "want=" + args[2].toInt32()];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "pwrite",
    aliases: ["pwrite$NOCANCEL", "__pwrite_nocancel"],
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
    name: "writev",
    aliases: ["writev$NOCANCEL", "__writev_nocancel"],
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd), "iovcnt=" + args[2].toInt32()];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "guarded_write_np",
    /* (fd, guard*, buf, nbyte) — the guard pointer shifts everything
       right by one compared to plain write. */
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd), "want=" + args[3].toInt32()];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "guarded_pwrite_np",
    /* (fd, guard*, buf, nbyte, offset) */
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [
        inv.fd,
        fdLabel(inv.fd),
        "want=" + args[3].toInt32(),
        "off=" + args[4].toInt32(),
      ];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "guarded_writev_np",
    /* (fd, guard*, iov, iovcnt) */
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, fdLabel(inv.fd), "iovcnt=" + args[3].toInt32()];
    },
    onLeave: (rv) => rv.toInt32(),
  },

  /* ---------------- metadata: stat ---------------- */
  /*
   * VERIFY: the 64-suffixed names are listed as aliases on the
   * assumption they share an address on arm64 (which was 64-bit inode
   * from the start). If the install report shows them installed
   * SEPARATELY rather than under `aliased`, run dis — if one chains into
   * the other you are double-counting.
   */
  {
    category: "filesystem",
    module: K,
    name: "stat",
    aliases: ["stat64"],
    onEnter: (args, inv) => {
      inv.sb = args[1];
      return [readCStr(args[0])];
    },
    onLeave: (rv, inv) => {
      const r = rv.toInt32();
      const d = r === 0 ? describeStatBuf(inv.sb) : null;
      return d === null ? r : r + " (" + d + ")";
    },
  },
  {
    category: "filesystem",
    module: K,
    name: "lstat",
    aliases: ["lstat64"],
    onEnter: (args, inv) => {
      inv.sb = args[1];
      return [readCStr(args[0])];
    },
    onLeave: (rv, inv) => {
      const r = rv.toInt32();
      const d = r === 0 ? describeStatBuf(inv.sb) : null;
      return d === null ? r : r + " (" + d + ")";
    },
  },
  {
    category: "filesystem",
    module: K,
    name: "fstat",
    aliases: ["fstat64"],
    onEnter: (args, inv) => {
      inv.sb = args[1];
      const fd = args[0].toInt32();
      return [fd, fdLabel(fd)];
    },
    onLeave: (rv, inv) => {
      const r = rv.toInt32();
      const d = r === 0 ? describeStatBuf(inv.sb) : null;
      return d === null ? r : r + " (" + d + ")";
    },
  },
  {
    category: "filesystem",
    module: K,
    name: "fstatat",
    aliases: ["fstatat64"],
    /* (dirfd, path, statbuf, flag) — path is args[1], not args[0] */
    onEnter: (args, inv) => {
      inv.sb = args[2];
      return [args[0].toInt32(), readCStr(args[1])];
    },
    onLeave: (rv, inv) => {
      const r = rv.toInt32();
      const d = r === 0 ? describeStatBuf(inv.sb) : null;
      return d === null ? r : r + " (" + d + ")";
    },
  },
  {
    category: "filesystem",
    module: K,
    name: "statfs",
    aliases: ["statfs64"],
    onEnter: (args) => [readCStr(args[0])],
    onLeave: (rv) => rv.toInt32(),
  },

  /* ---------------- metadata: attrlist ---------------- */
  {
    category: "filesystem",
    module: K,
    name: "getattrlist",
    onEnter: (args) => [readCStr(args[0]), describeAttrList(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "getattrlistat",
    /* (dirfd, path, attrList, buf, size, options) */
    onEnter: (args) => [
      args[0].toInt32(),
      readCStr(args[1]),
      describeAttrList(args[2]),
    ],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "fgetattrlist",
    onEnter: (args) => {
      const fd = args[0].toInt32();
      return [fd, fdLabel(fd), describeAttrList(args[1])];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "getattrlistbulk",
    /* Directory enumeration. (dirfd, attrList, buf, size, options) */
    onEnter: (args) => {
      const fd = args[0].toInt32();
      return [fd, fdLabel(fd), describeAttrList(args[1])];
    },
    onLeave: (rv) => rv.toInt32() /* number of entries returned */,
  },
  {
    category: "filesystem",
    module: K,
    name: "setattrlist",
    onEnter: (args) => [readCStr(args[0]), describeAttrList(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "getdirentries",
    aliases: ["__getdirentries64"],
    onEnter: (args) => {
      const fd = args[0].toInt32();
      return [fd, fdLabel(fd)];
    },
    onLeave: (rv) => rv.toInt32(),
  },

  /* ---------------- symlinks ---------------- */
  {
    category: "filesystem",
    module: K,
    name: "readlink",
    /* readlinkat is NOT an alias: (dirfd, path, buf, size), so args[0]
       is an int. Same shape of mistake as openat vs open. */
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

  /* ---------------- mutations ---------------- */
  {
    category: "filesystem",
    module: K,
    name: "unlink",
    onEnter: (args) => [readCStr(args[0])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "unlinkat",
    onEnter: (args) => [args[0].toInt32(), readCStr(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "rename",
    onEnter: (args) => [readCStr(args[0]), "->", readCStr(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "renameat",
    /* (fromfd, from, tofd, to) */
    onEnter: (args) => [readCStr(args[1]), "->", readCStr(args[3])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "renamex_np",
    /* Apple-only. The atomic-save pattern goes through here. */
    onEnter: (args) => [
      readCStr(args[0]),
      "->",
      readCStr(args[1]),
      hex(args[2].toInt32()),
    ],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "mkdir",
    /* mode here is a REAL fixed argument, unlike open's variadic mode */
    onEnter: (args) => [readCStr(args[0]), (args[1].toInt32() & 0o7777).toString(8)],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "mkdirat",
    onEnter: (args) => [args[0].toInt32(), readCStr(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "rmdir",
    onEnter: (args) => [readCStr(args[0])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "truncate",
    onEnter: (args) => [readCStr(args[0]), "len=" + args[1].toInt32()],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "ftruncate",
    onEnter: (args) => {
      const fd = args[0].toInt32();
      return [fd, fdLabel(fd), "len=" + args[1].toInt32()];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: K,
    name: "fsync",
    aliases: ["fsync$NOCANCEL", "fdatasync"],
    onEnter: (args) => {
      const fd = args[0].toInt32();
      return [fd, fdLabel(fd)];
    },
    onLeave: (rv) => rv.toInt32(),
  },

  /* ---------------- APFS copies ---------------- */
  /*
   * VERIFY existence: your earlier survey needles did not cover these,
   * so their absence from that output means nothing. clonefile copies a
   * file with ZERO read/write syscalls — APFS just shares the extents.
   * Module left null so the lookup searches globally; copyfile may live
   * in libcopyfile rather than libsystem_kernel.
   */
  {
    category: "filesystem",
    module: null,
    name: "clonefile",
    onEnter: (args) => [readCStr(args[0]), "->", readCStr(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: null,
    name: "clonefileat",
    onEnter: (args) => [readCStr(args[1]), "->", readCStr(args[3])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: null,
    name: "fclonefileat",
    onEnter: (args) => {
      const fd = args[0].toInt32();
      return [fd, fdLabel(fd), "->", readCStr(args[2])];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "filesystem",
    module: null,
    name: "copyfile",
    onEnter: (args) => [readCStr(args[0]), "->", readCStr(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },

  /* ---------------- memory mapping ---------------- */
  /*
   * A file-backed mapping is read through page faults, so a process can
   * consume an entire file with zero read() events. mmap is how you see
   * that happening.
   *
   * mmap(addr, len, prot, flags, fd, offset) — fd is args[4].
   * MAP_ANON means no file: those are ordinary allocations and get
   * filtered out below, or you drown.
   */
  {
    category: "memory",
    module: K,
    name: "mmap",
    onEnter: (args, inv) => {
      const flags = args[3].toInt32();
      inv.anon = (flags & MAP_ANON) !== 0;
      if (inv.anon) {
        inv.skip = true;
        return null;
      }
      const fd = args[4].toInt32();
      return [
        fdLabel(fd),
        "len=" + args[1].toInt32(),
        decodeProt(args[2].toInt32()),
        decodeMapFlags(flags),
        "off=" + args[5].toInt32(),
      ];
    },
    onLeave: (rv, inv) => (inv.skip ? null : rv.toString()),
  },
  {
    category: "memory",
    module: K,
    name: "mprotect",
    /* A page turning executable is worth seeing: JIT, or something
       less benign. */
    onEnter: (args) => [
      args[0].toString(),
      "len=" + args[1].toInt32(),
      decodeProt(args[2].toInt32()),
    ],
    onLeave: (rv) => rv.toInt32(),
  },

  /* ---------------- network ---------------- */
  {
    category: "network",
    module: K,
    name: "socket",
    onEnter: (args) => [
      "domain=" + args[0].toInt32(),
      "type=" + args[1].toInt32(),
      "proto=" + args[2].toInt32(),
    ],
    onLeave: (rv) => rv.toInt32() /* the new fd */,
  },
  {
    category: "network",
    module: K,
    name: "connect",
    aliases: ["connect$NOCANCEL", "__connect_nocancel"],
    onEnter: (args, inv) => {
      inv.fd = args[0].toInt32();
      return [inv.fd, parseSockaddr(args[1])];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "network",
    module: K,
    name: "bind",
    onEnter: (args) => [args[0].toInt32(), parseSockaddr(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "network",
    module: K,
    name: "accept",
    aliases: ["accept$NOCANCEL", "__accept_nocancel"],
    onEnter: (args, inv) => {
      inv.sa = args[1];
      return [args[0].toInt32()];
    },
    onLeave: (rv, inv) => {
      const fd = rv.toInt32();
      return fd >= 0 ? fd + " from " + parseSockaddr(inv.sa) : fd;
    },
  },
  {
    category: "network",
    module: K,
    name: "sendto",
    aliases: ["sendto$NOCANCEL", "__sendto_nocancel"],
    /* (fd, buf, len, flags, sockaddr*, addrlen) */
    onEnter: (args) => [
      args[0].toInt32(),
      "len=" + args[2].toInt32(),
      parseSockaddr(args[4]),
    ],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "network",
    module: K,
    name: "recvfrom",
    aliases: ["recvfrom$NOCANCEL", "__recvfrom_nocancel"],
    onEnter: (args, inv) => {
      inv.sa = args[4];
      return [args[0].toInt32(), "want=" + args[2].toInt32()];
    },
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "network",
    module: K,
    name: "sendmsg",
    aliases: ["sendmsg$NOCANCEL", "__sendmsg_nocancel"],
    onEnter: (args) => [args[0].toInt32()],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "network",
    module: K,
    name: "recvmsg",
    aliases: ["recvmsg$NOCANCEL", "__recvmsg_nocancel"],
    onEnter: (args) => [args[0].toInt32()],
    onLeave: (rv) => rv.toInt32(),
  },
  {
    category: "network",
    module: "libsystem_info.dylib",
    name: "getaddrinfo",
    /* DNS. Often more legible than the sockets it leads to, because you
       get the hostname rather than an IP. */
    onEnter: (args) => [readCStr(args[0]), readCStr(args[1])],
    onLeave: (rv) => rv.toInt32(),
  },

  /* ---------------- keychain and trust ---------------- */
  /*
   * Arguments are CFDictionaryRef. cfDescribe renders them, and releases
   * what CFCopyDescription hands back.
   *
   * DELIBERATELY NOT DESCRIBING THE RESULT. args[1] of
   * SecItemCopyMatching is an out-parameter holding the returned item —
   * which, with kSecReturnData set, is the secret itself. Dumping that
   * into your event log writes passwords and keys to disk. Observe the
   * query and the status; leave the payload alone.
   *
   * iOScope reports. It does not judge: an accessibility class that
   * looks weak may be exactly right for its use.
   */
  {
    category: "security",
    module: SEC,
    name: "SecItemCopyMatching",
    onEnter: (args) => [cfDescribe(args[0])],
    onLeave: (rv) => decodeSecStatus(rv.toInt32()),
  },
  {
    category: "security",
    module: SEC,
    name: "SecItemAdd",
    onEnter: (args) => [cfDescribe(args[0])],
    onLeave: (rv) => decodeSecStatus(rv.toInt32()),
  },
  {
    category: "security",
    module: SEC,
    name: "SecItemUpdate",
    onEnter: (args) => [cfDescribe(args[0]), "with", cfDescribe(args[1])],
    onLeave: (rv) => decodeSecStatus(rv.toInt32()),
  },
  {
    category: "security",
    module: SEC,
    name: "SecItemDelete",
    onEnter: (args) => [cfDescribe(args[0])],
    onLeave: (rv) => decodeSecStatus(rv.toInt32()),
  },
  {
    category: "security",
    module: SEC,
    name: "SecAccessControlCreateWithFlags",
    /* (allocator, protection, flags, error*) */
    onEnter: (args) => [cfDescribe(args[1]), "flags=" + hex(args[2].toInt32())],
    onLeave: (rv) => rv.toString(),
  },
  {
    category: "security",
    module: SEC,
    name: "SecTrustEvaluateWithError",
    onEnter: (args) => [args[0].toString()],
    onLeave: (rv) => (rv.toInt32() ? "trusted" : "NOT trusted"),
  },
];

/* ================================================================== */
/* Objective-C                                                        */
/* ================================================================== */
/*
 * Unlike every other hook here, ObjC methods have NO exported symbol.
 * -[NSURLSession dataTaskWithURL:] is not in any symbol table. You find
 * its address by asking the runtime at execution time:
 *
 *   objc_getClass("NSURLSession")   -> Class
 *   class_copyMethodList(cls, &n)   -> Method[]
 *   method_getImplementation(m)     -> IMP   <- the hook target
 *
 * Calling convention once you're there:
 *   x0 = self, x1 = _cmd (the selector), x2.. = real arguments
 *
 * NEVER hook objc_msgSend. One function, millions of calls per second,
 * and attaching to it hangs the process.
 */

const objcHooked = [];
const objcFailed = [];
let objcTruncated = false;

let _objc = null;

function objcInit() {
  if (_objc !== null) return _objc.ok;
  _objc = { ok: false };

  const need = {
    objc_getClass: ["pointer", ["pointer"]],
    objc_getMetaClass: ["pointer", ["pointer"]],
    class_getName: ["pointer", ["pointer"]],
    class_getSuperclass: ["pointer", ["pointer"]],
    class_copyMethodList: ["pointer", ["pointer", "pointer"]],
    method_getName: ["pointer", ["pointer"]],
    method_getImplementation: ["pointer", ["pointer"]],
    method_getTypeEncoding: ["pointer", ["pointer"]],
    sel_getName: ["pointer", ["pointer"]],
    object_getClass: ["pointer", ["pointer"]],
  };

  for (const n in need) {
    const a = resolveExport(n, null);
    if (a === null) return false;
    _objc[n] = new NativeFunction(a, need[n][0], need[n][1]);
  }

  const listAddr = resolveExport("objc_getClassList", null);
  _objc.objc_getClassList = listAddr
    ? new NativeFunction(listAddr, "int", ["pointer", "int"])
    : null;

  const freeAddr = resolveExport("free", null);
  _objc.free = freeAddr ? new NativeFunction(freeAddr, "void", ["pointer"]) : null;

  _objc.ok = true;
  return true;
}

/* ---- type encodings ---------------------------------------------- */
/*
 * A method signature is a compact string: "v24@0:8@16" means returns
 * void, 24 bytes of arguments, an object at offset 0 (self), a selector
 * at 8 (_cmd), an object at 16 (the first real argument).
 *
 * You need this to know whether args[2] is a pointer you can safely
 * dereference or an integer that would fault if you tried.
 *
 * Returns [returnType, '@'(self), ':'(_cmd), arg1, arg2, ...]
 */
function skipOneType(enc, i) {
  const n = enc.length;
  if (i >= n) return i;
  const c = enc[i];
  if (c === "{" || c === "(" || c === "[") {
    const close = c === "{" ? "}" : c === "(" ? ")" : "]";
    let depth = 0;
    while (i < n) {
      if (enc[i] === c) depth++;
      else if (enc[i] === close) {
        depth--;
        if (depth === 0) return i + 1;
      }
      i++;
    }
    return i;
  }
  if (c === "@" && enc[i + 1] === '"') {
    i += 2;
    while (i < n && enc[i] !== '"') i++;
    return i + 1;
  }
  if (c === "^") return skipOneType(enc, i + 1);
  return i + 1;
}

function parseTypeEncoding(enc) {
  if (!enc) return [];
  const out = [];
  let i = 0;
  const n = enc.length;
  while (i < n) {
    const c = enc[i];
    if (c >= "0" && c <= "9") { i++; continue; }        // sizes and offsets
    if ("rnNoORV".indexOf(c) !== -1) { i++; continue; } // const, in, out...
    if (c === "@" && enc[i + 1] === '"') {              // @"NSString"
      i += 2;
      while (i < n && enc[i] !== '"') i++;
      i++;
      out.push("@");
      continue;
    }
    if (c === "^") {                                     // pointer to T
      out.push("^");
      i = skipOneType(enc, i + 1);
      continue;
    }
    if (c === "{" || c === "(" || c === "[") {
      out.push(c);
      i = skipOneType(enc, i);
      continue;
    }
    out.push(c);
    i++;
  }
  return out;
}

/* ---- rendering ---------------------------------------------------- */
/*
 * The receiver's class comes from object_getClass + class_getName. That
 * is a pure table lookup: no user code runs, so it cannot recurse or
 * have side effects.
 *
 * Calling -description (which cfDescribe does, via toll-free bridging)
 * DOES run user code inside your hook. It can allocate, take locks, and
 * re-enter your own hooks. Opt-in only, and never in a hot path.
 */
function objcClassName(obj) {
  if (obj.isNull()) return "nil";
  try {
    const cls = _objc.object_getClass(obj);
    if (cls.isNull()) return "?";
    return _objc.class_getName(cls).readUtf8String();
  } catch (e) {
    return "?";
  }
}

function renderObjcValue(code, val) {
  switch (code) {
    case "@": return config.objcDescribe ? cfDescribe(val) : objcClassName(val);
    case "#": return "Class(" + safe(() => _objc.class_getName(val).readUtf8String(), "?") + ")";
    case ":": return safe(() => _objc.sel_getName(val).readUtf8String(), "?");
    case "*": return readCStr(val);
    case "B":
    case "c": return val.toInt32() ? "YES" : "NO";
    case "i": case "s": case "l": case "q": return val.toInt32();
    case "I": case "S": case "L": case "Q": return val.toUInt32();
    case "v": return undefined;
    default: return val.toString();
  }
}

/*
 * Arguments are read from x2 onward. That is correct ONLY for integer
 * and pointer types. Floats and doubles travel in v0-v7, and structs
 * passed by value consume several registers — either one shifts every
 * argument after it. Rather than print confident nonsense, stop.
 */
const UNSAFE_CODES = "fd{[(";

function renderObjcArgs(types, args) {
  const out = [objcClassName(args[0])]; // receiver
  for (let i = 3; i < types.length; i++) {
    const code = types[i];
    if (UNSAFE_CODES.indexOf(code) !== -1) {
      out.push("<" + code + " and beyond: not register-readable>");
      break;
    }
    const idx = i - 1; // types[3] is args[2]
    if (idx > 7) { out.push("<stack args>"); break; }
    out.push(renderObjcValue(code, args[idx]));
  }
  return out;
}

/* ---- runtime queries ---------------------------------------------- */
function methodsOf(cls) {
  const out = [];
  if (cls.isNull()) return out;
  const nPtr = Memory.alloc(4);
  const list = _objc.class_copyMethodList(cls, nPtr);
  if (list.isNull()) return out;
  const n = nPtr.readU32();
  for (let i = 0; i < n; i++) {
    try {
      const m = list.add(i * Process.pointerSize).readPointer();
      if (m.isNull()) continue;
      out.push({
        sel: _objc.sel_getName(_objc.method_getName(m)).readUtf8String(),
        types: safe(() => _objc.method_getTypeEncoding(m).readUtf8String(), ""),
        imp: _objc.method_getImplementation(m),
      });
    } catch (e) {}
  }
  if (_objc.free) _objc.free(list); // class_copyMethodList mallocs. Copy means yours.
  return out;
}

/* ---- attaching ----------------------------------------------------- */
function attachObjcMethod(label, encoding, imp) {
  if (objcHooked.length >= (config.objcMax || 400)) {
    objcTruncated = true;
    return false;
  }
  const types = parseTypeEncoding(encoding);
  try {
    Interceptor.attach(imp, {
      onEnter(args) {
        guard(() => {
          if (!wanted("objc")) return;
          this.ev = {
            category: "objc",
            symbol: label,
            args: renderObjcArgs(types, args),
            caller: describeAddress(this.returnAddress, true),
            backtrace: captureBacktrace(this.context),
          };
        });
      },
      onLeave(retval) {
        guard(() => {
          if (!this.ev) return;
          const r = renderObjcValue(types[0] || "?", retval);
          if (r !== undefined) this.ev.ret = r;
          emit(this.ev);
          this.ev = null;
        });
      },
    });
    objcHooked.push(label);
    return true;
  } catch (e) {
    objcFailed.push(label + ": " + e.message);
    return false;
  }
}

/*
 * class_copyMethodList returns ONLY methods defined on that exact class.
 * Inherited methods live on the superclass, so a call you expected may be
 * implemented three classes up. --objc-depth walks the chain.
 */
function installByClass(name, depth) {
  const cname = Memory.allocUtf8String(name);
  let cls = _objc.objc_getClass(cname);
  const meta = _objc.objc_getMetaClass(cname);

  if (cls.isNull() && meta.isNull()) {
    objcFailed.push(name + ": class not found in this process");
    return 0;
  }

  let n = 0;
  let level = 0;
  while (!cls.isNull() && level <= (depth || 0)) {
    const owner = safe(() => _objc.class_getName(cls).readUtf8String(), name);
    for (const m of methodsOf(cls))
      if (attachObjcMethod("-[" + owner + " " + m.sel + "]", m.types, m.imp)) n++;
    cls = _objc.class_getSuperclass(cls);
    level++;
  }

  if (!meta.isNull())
    for (const m of methodsOf(meta))
      if (attachObjcMethod("+[" + name + " " + m.sel + "]", m.types, m.imp)) n++;

  return n;
}

/*
 * The cheap path. Needs no bridge, accepts globs, but gives no type
 * encoding — so arguments beyond the receiver are not rendered.
 */
function installByResolver(query) {
  let n = 0;
  try {
    const r = new ApiResolver("objc");
    for (const m of r.enumerateMatches(query))
      if (attachObjcMethod(m.name, "", m.address)) n++;
  } catch (e) {
    objcFailed.push(query + ": " + e.message);
  }
  return n;
}

function installObjC(filter) {
  /* NB: not `ObjC.available` — there is no ObjC global in Frida 17. */
  if (!objcAvailable()) {
    send({ kind: "agent-error", message: "ObjC runtime not available" });
    return;
  }
  if (!objcInit()) {
    send({ kind: "agent-error", message: "could not resolve libobjc functions" });
    return;
  }

  const specs = String(filter).split(",").map((s) => s.trim()).filter(Boolean);
  for (const s of specs) {
    if (s.indexOf("[") !== -1) installByResolver(s); // glob: -[NSURLSession *]
    else installByClass(s, config.objcDepth || 0);   // plain class name
  }

  send({
    kind: "objc-install",
    hooked: objcHooked.length,
    failed: objcFailed,
    truncated: objcTruncated,
    sample: objcHooked.slice(0, 12),
  });
}

/* ================================================================== */
/* RPC surface                                                        */
/* ================================================================== */
rpc.exports = {
  meta() {
    return {
      pid: Process.id,
      arch: Process.arch /* 'arm64' even on arm64e — PAC is still live */,
      platform: Process.platform,
      pointerSize: Process.pointerSize,
      pageSize: Process.pageSize /* 16384 here, not 4096 */,
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
    /* Closest thing iOS has to /proc/<pid>/maps. */
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
    return {
      installed,
      failed,
      aliased,
      counts: {
        installed: installed.length,
        failed: failed.length,
        aliased: aliased.length,
      },
    };
  },

  drain() {
    flush();
  },

  /* ---- introspection ---- */

  /* What does this image actually export? Your libSystem is the
     authority, not anybody's list. */
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

  /* Stripped addresses, so aliases are distinguishable from distinct
     functions. */
  addrs(names, moduleName) {
    const m = Process.findModuleByName(moduleName || K);
    const out = {};
    names.forEach((n) => {
      const a = m ? m.findExportByName(n) : null;
      out[n] = a === null ? null : a.strip().toString();
    });
    return out;
  },

  /* Read the stub. 'mov x16, #N' + 'svc #0x80' is a raw syscall with N
     as the number; a stack frame prologue means a wrapper that chains
     elsewhere. */
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

  /* Current fd -> path mapping. If reads show <unnamed fd> for a file
     you know was opened, look here first. */
  fdtable() {
    const out = {};
    fdTable.forEach((v, k) => {
      out[k] = v;
    });
    return out;
  },

  /* Proof that fcntl needs the '...' marker: Apple ARM64 passes variadic
     arguments on the stack, so the three-register declaration reads
     garbage and returns -1. */
  testfd(fd) {
    const a = resolveExport("fcntl", K);
    if (a === null) return { error: "fcntl not found" };
    const bad = new NativeFunction(a, "int", ["int", "int", "pointer"]);
    const good = new NativeFunction(a, "int", ["int", "int", "...", "pointer"]);
    const b1 = Memory.alloc(PATH_MAX);
    const b2 = Memory.alloc(PATH_MAX);
    return {
      without_varargs: {
        rv: bad(fd, F_GETPATH, b1),
        path: b1.readUtf8String(),
      },
      with_varargs: { rv: good(fd, F_GETPATH, b2), path: b2.readUtf8String() },
    };
  },

  /* Sanity-check the struct stat offsets against a file of known size.
     Wrong offsets give a plausible wrong number, not an error. */
  teststat(path) {
    const a = resolveExport("stat", K) || resolveExport("stat64", K);
    if (a === null) return { error: "stat not found" };
    const fn = new NativeFunction(a, "int", ["pointer", "pointer"]);
    const sb = Memory.alloc(256);
    const rv = fn(Memory.allocUtf8String(path), sb);
    return {
      rv: rv,
      decoded: describeStatBuf(sb),
      raw_first_128: sb.readByteArray(128),
    };
  },

  symbolicate(addresses) {
    return addresses.map((s) => describeAddress(ptr(s), false));
  },

  symstats() {
    const out = {};
    symIndex.forEach((v, k) => { out[k] = v.length; });
    return { indexed_modules: out, cached_addresses: symCache.size };
  },
    /* What classes exist here? Run this before deciding what to hook. */
  objcclasses(pattern, limit) {
    if (!objcAvailable() || !objcInit() || !_objc.objc_getClassList)
      return { error: "objc runtime unavailable" };
    const total = _objc.objc_getClassList(NULL, 0);
    const buf = Memory.alloc(total * Process.pointerSize);
    const got = _objc.objc_getClassList(buf, total);
    const re = pattern ? new RegExp(pattern, "i") : null;
    const out = [];
    for (let i = 0; i < got && out.length < (limit || 200); i++) {
      const n = safe(() => _objc.class_getName(
        buf.add(i * Process.pointerSize).readPointer()).readUtf8String(), null);
      if (n && (!re || re.test(n))) out.push(n);
    }
    return { total: total, matched: out.sort() };
  },

  /* Method list with encodings, without hooking anything. */
  objcmethods(className) {
    if (!objcAvailable() || !objcInit()) return { error: "objc runtime unavailable" };
    const c = Memory.allocUtf8String(className);
    const render = (list, kind) => list.map((m) => ({
      name: kind + "[" + className + " " + m.sel + "]",
      types: m.types,
      parsed: parseTypeEncoding(m.types).join(" "),
      imp: m.imp.strip().toString(),
    }));
    return {
      instance: render(methodsOf(_objc.objc_getClass(c)), "-"),
      klass: render(methodsOf(_objc.objc_getMetaClass(c)), "+"),
    };
  },
};