/*
 * iOScope agent — milestone 0/1
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
 */

'use strict';

const T0 = Date.now();

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
    if (typeof Module.getGlobalExportByName === 'function') {
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
    send({ kind: 'agent-error', message: String(e), stack: e.stack });
  } finally {
    busy.delete(tid);
  }
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
  send({ kind: 'events', events: events });
}

function emit(ev) {
  if (config.categories && config.categories.indexOf(ev.category) === -1) return;
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
 */
function describeAddress(addr) {
  const m = Process.findModuleByAddress(addr);
  if (m === null) return { raw: addr.toString() };
  return {
    raw: addr.toString(),
    module: m.name,
    offset: '0x' + addr.sub(m.base).toString(16),
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
const installed = [];
const failed = [];

function hook(spec) {
  // libc symbols on iOS have variants. open() is frequently reached via
  // open$NOCANCEL; if you only hook the plain name you will conclude the
  // app does no file I/O.
  const names = spec.aliases ? [spec.name].concat(spec.aliases) : [spec.name];

  let any = false;
  for (const name of names) {
    const addr = resolveExport(name, spec.module);
    if (addr === null) continue;
    try {
      Interceptor.attach(addr, {
        onEnter(args) {
          guard(() => {
            this.ev = {
              category: spec.category,
              symbol: spec.name,
              args: spec.onEnter ? spec.onEnter(args) : [],
              caller: describeAddress(this.returnAddress),
              backtrace: captureBacktrace(this.context),
            };
          });
        },
        onLeave(retval) {
          guard(() => {
            if (!this.ev) return;
            if (spec.onLeave) this.ev.ret = spec.onLeave(retval);
            emit(this.ev);
            this.ev = null;
          });
        },
      });
      installed.push(name);
      any = true;
    } catch (e) {
      failed.push(name + ': ' + e.message);
    }
  }
  if (!any) failed.push(spec.name + ': symbol not found');
}

/* ------------------------------------------------------------------ */
/* Argument readers                                                    */
/* ------------------------------------------------------------------ */
/*
 * Reading a char* from a hooked process can fault: the pointer may be
 * null, unmapped, or pointing at a page that has been unmapped between
 * the call and your read. Always go through this.
 */
function readCStr(ptr_) {
  if (ptr_.isNull()) return '(null)';
  try {
    const s = ptr_.readUtf8String();
    return s === null ? '(null)' : JSON.stringify(s);
  } catch (e) {
    return '<unreadable ' + ptr_ + '>';
  }
}

/* ------------------------------------------------------------------ */
/* THE HOOKS                                                           */
/* ------------------------------------------------------------------ */
/*
 * One worked example below. The rest of Phase 1 is you filling this in.
 * Do them one at a time, and run the tool after each one.
 */
const SPECS = [
  {
    category: 'filesystem',
    name: 'open',
    aliases: ['open$NOCANCEL', '__open', '__open_nocancel', 'openat'],
    onEnter: (args) => [readCStr(args[0]), '0x' + args[1].toInt32().toString(16)],
    onLeave: (retval) => retval.toInt32(),
  },

  // TODO close   — trivial, do it to prove you understand the shape
  // TODO read / write / pread / pwrite
  // TODO stat / lstat / fstat / stat64 variants
  // TODO socket / connect / send / recv
  //      connect() takes a struct sockaddr* — you have to parse sa_family
  //      then read sockaddr_in or sockaddr_in6. This is the first hook
  //      that forces you to read a real kernel struct.
  // TODO SecItemCopyMatching / SecItemAdd  (module: 'Security')
  //      These take CFDictionaryRef. You cannot just readUtf8String them.
  //      You will need ObjC bridging or CFCopyDescription.
];

/* ------------------------------------------------------------------ */
/* Objective-C observation                                             */
/* ------------------------------------------------------------------ */
/*
 * Deliberately left empty.
 *
 * Do NOT reach for objc_msgSend. It is called millions of times per
 * second and hooking it globally will hang the process. The working
 * approach is to resolve a specific class, walk its method list, and
 * attach to individual IMPs. Milestone 5.
 */
function installObjC(filter) {
  if (!ObjC.available) {
    send({ kind: 'agent-error', message: 'ObjC runtime not available' });
    return;
  }
  // TODO
}

/* Frida 17 moved the ObjC/Swift bridges out of the core runtime into
 * separate packages. Until we bundle them, answer the question directly:
 * is the runtime mapped into this process at all? */
function objcAvailable() {
  return resolveExport('objc_msgSend', null) !== null;
}

function swiftAvailable() {
  return Process.findModuleByName('libswiftCore.dylib') !== null;
}

/* ------------------------------------------------------------------ */
/* RPC surface                                                         */
/* ------------------------------------------------------------------ */
rpc.exports = {
  meta() {
    return {
      pid: Process.id,
      arch: Process.arch,          // expect 'arm64' — Frida reports arm64e as arm64
      platform: Process.platform,
      pointerSize: Process.pointerSize,
      pageSize: Process.pageSize,
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
    return Process.enumerateRanges('r--').map((r) => ({
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
    return { installed: installed, failed: failed };
  },

  drain() {
    flush();
  },
};