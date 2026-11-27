# The commonwire host Worker in local workerd, for the conformance suite. Secrets come from the environment;
# Durable Object storage goes to the `storage` directory given with --directory-path.
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .host),
    (name = "internet", network = (allow = ["public", "private", "local"])),
    (name = "storage", disk = (writable = true)),
  ],
  sockets = [(name = "http", address = "127.0.0.1:4191", http = (), service = "main")],
);

const host :Workerd.Worker = (
  modules = [
    (name = "index.js", esModule = embed "pkg/index.js"),
    (name = "cw_host.js", esModule = embed "pkg/cw_host.js"),
    (name = "cw_host_bg.wasm", wasm = embed "pkg/cw_host_bg.wasm"),
  ],
  compatibilityDate = "2026-08-01",
  bindings = [
    (name = "HOST_SECRET", fromEnvironment = "CW_HOST_SECRET"),
    (name = "CLAIM_DIGEST", fromEnvironment = "CW_CLAIM_DIGEST"),
    (name = "VAPID", fromEnvironment = "CW_VAPID"),
    (name = "ORIGIN", fromEnvironment = "CW_ORIGIN"),
    (name = "HOST", durableObjectNamespace = "Host"),
    (name = "TENANT", durableObjectNamespace = "Tenant"),
  ],
  durableObjectNamespaces = [
    (className = "Host", uniqueKey = "commonwire-host", enableSql = true),
    (className = "Tenant", uniqueKey = "commonwire-tenant", enableSql = true),
  ],
  durableObjectStorage = (localDisk = "storage"),
  globalOutbound = "internet",
);
