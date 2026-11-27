# A New Internet host

The host for [anewinter.net](https://anewinter.net). It stores people's encrypted profiles and groups and serves them to the people they share them with.

A host runs as a Worker on your Cloudflare account or as the `commonwire` program on your own machine. Both run the same code, `rust/cw-host`.

## Run it on Cloudflare

In [anewinter.net](https://anewinter.net), choose **Set up on Cloudflare** on the start page, or **Settings → Hosting → Set up a host on Cloudflare**. Sign in with Cloudflare and pick an account. The app deploys the host to that account and claims it.

Your account then has:

- A Worker built from `worker/index.ts` and `rust/cw-host` compiled to WebAssembly. `scripts/sl worker` builds the same files.
- Two SQLite-backed Durable Object classes: `Host` for the host's own state and `Tenant`, one per profile or group it keeps.
- Three secrets made at setup: `HOST_SECRET`, `CLAIM_DIGEST` and `VAPID` (the Web Push key).

To update the host, choose **Update on Cloudflare** under it in **Settings → Hosting**.

## Run it on your own machine

Point a domain name at the machine and open port 443. Download `commonwire` for your system:

- macOS, Apple silicon: https://anewinter.net/download/commonwire-macos-arm64
- macOS, Intel: https://anewinter.net/download/commonwire-macos-amd64
- Linux, x86-64: https://anewinter.net/download/commonwire-linux-amd64
- Linux, ARM64: https://anewinter.net/download/commonwire-linux-arm64
- Windows, x86-64: https://anewinter.net/download/commonwire-windows-amd64.exe

```sh
curl -fLo commonwire https://anewinter.net/download/commonwire-macos-arm64
chmod +x commonwire
./commonwire host init --domain host.example.com
./commonwire serve
```

`host init` prints a link. Open it on your device to claim the host. `serve` gets its certificate through ACME and keeps its data in SQLite.

To build `commonwire` yourself instead, with a C compiler and Rust installed, run `cargo build --locked --profile native -p commonwire` in `rust/`. The program is `rust/target/native/commonwire`.

To start the host at boot, run `sudo ./commonwire service install`. It installs a LaunchDaemon on macOS, a systemd unit on Linux or a Windows service.

## Delete it

In [anewinter.net](https://anewinter.net), choose **Delete this host** under it in **Settings → Hosting**. The app lists what goes, asks you to type the host's name and confirm with your passkey or recovery key, and sends `DELETE /admin/host`: the host deletes every profile and group it stores and its own records, and answers 410 to every request afterwards. A host on Cloudflare needs a Cloudflare sign-in, and the app then deletes its Worker with its Durable Objects. On your own machine, run `sudo ./commonwire service uninstall` and delete the data folder to remove the program.

## Build and test

You need Rust (the version in `rust/rust-toolchain.toml`), `wasm-bindgen-cli` 0.2.126, `wasm-opt` from Binaryen, Bun and Python 3.

```sh
scripts/sl worker             # the Worker, in out/worker
scripts/sl build              # commonwire for this machine
scripts/sl test conformance   # the conformance suite on commonwire and on the Worker in workerd
scripts/sl test hosts         # unit tests, the conformance suite and the host budgets
```

## Docs

- [docs/hosts.md](docs/hosts.md): the host API
- [docs/format.md](docs/format.md): keys, tokens and encrypted formats

## License

[PolyForm Shield License 1.0.0](LICENSE.md)
