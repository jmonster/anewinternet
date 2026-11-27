#!/usr/bin/env python3
"""Host exit checks (docs/hosts.md): the conformance suite against native commonwire and local workerd with
identical outcomes, no plaintext in either runtime's storage, the host budgets, and writes through restarts.

Usage: hosts.py <cargo release dir> <worker package dir> <scratch dir> [conformance]
With "conformance", only the conformance suite and the plaintext check run.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN, WORKER, SCRATCH = sys.argv[1:4]
ONLY_CONFORMANCE = sys.argv[4:] == ["conformance"]
NATIVE_PORT, WORKERD_PORT = 4190, 4191
MIB = 1024 * 1024
failures = []


def run(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=kw.pop("timeout", 600), **kw)


def wait_up(port, deadline=20):
    end = time.time() + deadline
    while time.time() < end:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/push/key", timeout=1)
            return
        except Exception as e:
            if getattr(e, "code", None):
                return
            time.sleep(0.1)
    raise SystemExit(f"host on port {port} did not start")


def init(data, port):
    shutil.rmtree(data, ignore_errors=True)
    out = run(f"{BIN}/commonwire", "host", "init", "--origin", f"http://127.0.0.1:{port}", "--data", data).stdout
    claim = re.search(r"claim=([A-Za-z0-9_-]+)\.", out).group(1)
    return claim, json.load(open(os.path.join(data, "host.json")))


class Host:
    def __init__(self, kind):
        self.kind = kind
        self.dir = os.path.join(SCRATCH, kind)
        self.port = NATIVE_PORT if kind == "native" else WORKERD_PORT
        self.base = f"http://127.0.0.1:{self.port}"
        self.proc = None

    def start(self, fresh=True):
        if self.kind == "native":
            if fresh:
                self.claim, _ = init(self.dir, self.port)
            self.storage = self.dir
            cmd = [f"{BIN}/commonwire", "serve", "--data", self.dir, "--http", f"127.0.0.1:{self.port}"]
            env = os.environ
        else:
            shutil.rmtree(self.dir, ignore_errors=True)
            self.claim, cfg = init(os.path.join(self.dir, "cfg"), self.port)
            self.storage = os.path.join(self.dir, "storage")
            os.makedirs(self.storage)
            pkg = os.path.join(ROOT, "tests/hosts/pkg")
            shutil.rmtree(pkg, ignore_errors=True)
            shutil.copytree(WORKER, pkg)
            cmd = [os.path.join(ROOT, "node_modules/.bin/workerd"), "serve", os.path.join(ROOT, "tests/hosts/worker.capnp"),
                   "--directory-path", f"storage={self.storage}"]
            env = dict(os.environ, CW_HOST_SECRET=cfg["secret"], CW_CLAIM_DIGEST=cfg["claim"], CW_VAPID=cfg["vapid"],
                       CW_ORIGIN=self.base)
        self.log = open(os.path.join(SCRATCH, f"{self.kind}-serve.log"), "w" if fresh else "a")
        self.proc = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT, env=env)
        began = time.monotonic()
        wait_up(self.port)
        self.started_in = time.monotonic() - began
        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self.proc = None
        if self.kind == "workerd":
            shutil.rmtree(os.path.join(ROOT, "tests/hosts/pkg"), ignore_errors=True)

    def rss(self):
        return int(run("ps", "-o", "rss=", "-p", str(self.proc.pid)).stdout.strip()) * 1024

    def suite(self, *args, timeout=600):
        out = run(f"{BIN}/cw-conformance", *args, "--base", self.base, timeout=timeout).stdout
        return json.loads(out)

    def log_text(self):
        self.log.flush()
        return open(self.log.name).read()


def plaintext(directory):
    """Files under `directory` that contain the suite's marker."""
    hits = []
    for base, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(base, name)
            if name in ("host.json",):
                continue
            with open(path, "rb") as f:
                if b"MARKER" in f.read():
                    hits.append(os.path.relpath(path, directory))
    return hits


def budget(name, value, limit, unit=""):
    ok = value <= limit
    print(f"budget {name}: {value}{unit} (limit {limit}{unit}) {'ok' if ok else 'OVER'}")
    if not ok:
        failures.append(name)


def conformance():
    reports = {}

    def one(kind):
        host = Host(kind).start()
        try:
            reports[kind] = host.suite("check", "--claim", host.claim)
            hits = plaintext(host.storage)
            print(f"{kind}: {reports[kind]['checks']} checks, digest {reports[kind]['digest']}, plaintext files: {hits or 'none'}")
            if hits:
                failures.append(f"{kind} plaintext")
        finally:
            host.stop()

    # The suite waits out a socket's 75 s silence once on each runtime, so the two run at once.
    with ThreadPoolExecutor(2) as pool:
        for done in [pool.submit(one, kind) for kind in ("native", "workerd")]:
            done.result()
    a, b = reports["native"]["outcomes"], reports["workerd"]["outcomes"]
    with open(os.path.join(SCRATCH, "outcomes.json"), "w") as f:
        json.dump(a, f, indent=1, sort_keys=True)
    differ = sorted(k for k in a.keys() | b.keys() if a.get(k) != b.get(k))
    for k in differ:
        print(f"differs {k}: native={a.get(k)!r} workerd={b.get(k)!r}")
    if differ:
        failures.append("runtimes differ")
    else:
        print(f"conformance: identical on native and workerd ({len(a)} checks)")


def native_budgets():
    budget("commonwire binary", round(os.path.getsize(f"{BIN}/commonwire") / MIB, 2), 15, " MiB")
    host = Host("native").start()
    try:
        host.suite("seed", "--claim", host.claim, "--tenants", "10")
        time.sleep(3)
        budget("idle RSS with 10 tenants", round(host.rss() / MIB, 1), 15, " MiB")
    finally:
        host.stop()
    host = Host("native").start()
    try:
        seeded = os.path.join(SCRATCH, "seeded.json")
        # Seeding 100 tenants from one address waits out the per-IP limit on signed requests once.
        with open(seeded, "w") as f:
            json.dump(host.suite("seed", "--claim", host.claim, "--tenants", "100"), f)
        peak = [0]
        loader = subprocess.Popen(
            [f"{BIN}/cw-conformance", "load", "--base", host.base, "--seeded", seeded,
             "--readers", "1000", "--seconds", "15", "--interval-ms", "100"],
            stdout=subprocess.PIPE, text=True)
        while loader.poll() is None:
            peak[0] = max(peak[0], host.rss())
            time.sleep(0.25)
        result = json.loads(loader.stdout.read())
        print(f"load, each reader every 100 ms across 100 tenants: {result}")
        saturation = host.suite("load", "--seeded", seeded, "--readers", "1000", "--seconds", "10", "--interval-ms", "0")
        print(f"saturation, readers back to back (reported, not a budget): {saturation}")
        budget("RSS with 1,000 readers across 100 tenants", round(peak[0] / MIB, 1), 120, " MiB")
        budget("p99 head read with 1,000 readers across 100 tenants", round(result["p99_us"] / 1000, 2), 10, " ms")
        if result["errors"] or not result["requests"]:
            failures.append("load errors")
    finally:
        host.stop()


def restarts():
    """Owners and friends write while the host is stopped or killed six times; nothing acknowledged may be lost."""
    host = Host("native").start()
    seconds, count = 35, 6
    try:
        writer = subprocess.Popen([f"{BIN}/cw-conformance", "restarts", "--base", host.base, "--claim", host.claim,
                                   "--tenants", "40", "--seconds", str(seconds)], stdout=subprocess.PIPE, text=True)
        slowest = 0
        for i in range(count):
            time.sleep(seconds / (count + 1))
            if i % 2 == 0:
                host.stop()
            else:
                host.proc.kill()
                host.proc.wait(timeout=10)
            host.start(fresh=False)
            slowest = max(slowest, host.started_in)
        result = json.loads(writer.communicate(timeout=seconds + 120)[0])
        print(f"writes through {count} restarts: {result}")
        budget("serving after a restart", round(slowest, 3), 10, " s")
        if result["lost"] or result["errors"] or writer.returncode:
            failures.append("writes lost through restarts")
    finally:
        host.stop()


def workerd_idle():
    host = Host("workerd").start()
    try:
        result = host.suite("idle", "--claim", host.claim, "--seconds", "40", timeout=120)
        starts = host.log_text().count("tenant object started")
        print(f"idle sockets: {result['pongs']} pongs in 40 s; tenant object starts: {starts}")
        # One start for the setup traffic, none for 40 s of pings, one for the request afterwards.
        budget("Durable Object wake-ups from pinging sockets", starts - 2, 0)
        if result["pongs"] < 35 or starts < 2:
            failures.append("idle sockets")
    finally:
        host.stop()


def main():
    shutil.rmtree(SCRATCH, ignore_errors=True)
    os.makedirs(SCRATCH)
    conformance()
    if not ONLY_CONFORMANCE:
        native_budgets()
        restarts()
        workerd_idle()
    if failures:
        raise SystemExit(f"host checks failed: {', '.join(failures)}")
    print("host checks passed")


main()
