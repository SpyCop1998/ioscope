# vPhone iOS RE — Quick README

## Environment

* Host: Apple Silicon Mac
* iOS: `26.6`
* cloudOS: `26.4`
* Variant: `jb`
* VM IP: `192.168.64.7`
* SSH port: `22222`
* Frida server: `17.17.0`

---

## 1. SSH

From Mac:

```bash
ssh -p 22222 mobile@192.168.64.7
```

Password:

```text
alpine
```

---

## 2. Get Root

Check permissions:

```bash
/var/jb/usr/bin/sudo -l
```

Expected:

```text
(ALL) ALL
```

Get root:

```bash
/var/jb/usr/bin/sudo /iosbinpack64/bin/bash
```

Verify:

```bash
whoami
```

Expected:

```text
root
```

> `sudo su` and `sudo -s` don't work on this VM because `su` and `/bin/sh` aren't available.

---

## 3. Frida Server

Check the automatically running server:

```bash
ps aux | grep '[f]rida-server'
```

The default server on `27042` is supervised and automatically respawns if killed.

For Mac → VM access, start another instance on `27043`:

```bash
/var/jb/usr/sbin/frida-server --listen=0.0.0.0:27043
```

**Keep this terminal open.**

---

## 4. Test From Mac

```bash
frida-ps -H 192.168.64.7:27043
```

If you see the iOS process list, Frida connectivity is working.

---

## 5. Attach to a Process

Find a PID:

```bash
frida-ps -H 192.168.64.7:27043
```

Attach:

```bash
frida -H 192.168.64.7:27043 -p <PID> -l test.js
```

Example:

```bash
frida -H 192.168.64.7:27043 -p 1547 -l test.js
```

---

## Mental Model

```text
Mac
 │
 ├── SSH :22222 ──► iOS VM
 │                    │
 │                    └── mobile
 │                         │
 │                         └── sudo → root
 │
 └── Frida :27043 ──► frida-server
                           │
                           └── iOS process
```

**SSH = access**
**sudo = root**
**Frida = instrumentation**
