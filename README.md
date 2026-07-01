# hfs-tls-tunnel

A stunnel-style TLS front-end for HFS (HTTP File Server). It opens one or more
TLS listeners that decrypt incoming traffic and forward it, in plaintext, to
local backend services — reusing the same certificate and private key that
HFS itself is already configured with.

This is meant for people running other plaintext TCP services (media servers,
internal dashboards, etc.) on the same machine as HFS, who want to put TLS in
front of them without standing up a separate reverse proxy or a second copy
of stunnel.

## Requirements

- HFS with `cert` and `private_key` already configured (Admin panel → HTTPS,
  or set directly in `config.yaml`). This plugin does not generate or manage
  certificates — it only reads the ones HFS already has.
- Node's built-in `tls` and `net` modules (no extra dependencies).

## Install

Copy this plugin's folder into HFS's `plugins` directory, next to
`config.yaml`. For development, you can instead place it directly at
`.hfs/plugins/hfs-tls-tunnel/`.

Once installed, configure tunnels from the HFS Admin panel (Plugins →
hfs-tls-tunnel → Configure), or by editing `config.yaml` directly.

## Configuration

Each row in the `tunnels` list defines one independent TLS listener:

| Field | Description |
|---|---|
| **Listen address** | Interface to bind to. `0.0.0.0` (default) accepts connections on all interfaces. Set a specific local IP to restrict this tunnel to one interface. |
| **Listen port (TLS)** | The port clients connect to over TLS. Must be unique across all tunnels. |
| **Backend host** | Where to forward decrypted traffic. Defaults to `127.0.0.1`. |
| **Backend port (plain)** | The plaintext port your backend service is listening on. |
| **Client CA cert path** *(optional)* | If set, requires connecting clients to present a certificate signed by this CA — see [Mutual TLS](#mutual-tls-optional) below. Leave blank for normal TLS. |
| **Disabled** | Turn a tunnel off without deleting its config. |

Example: expose a media server that only listens on plaintext port `8096` at
`https://yourserver:8443`:

```yaml
tunnels:
  - listen_host: 0.0.0.0
    listen_port: 8443
    target_host: 127.0.0.1
    target_port: 8096
```

Add as many rows as you have services. Duplicate `listen_port` entries and
incomplete rows (missing port numbers) are skipped, with a log message
explaining why.

## How it works

Each tunnel is a Node `tls.Server` that, on every incoming connection, opens
a plaintext `net` connection to the configured backend and pipes bytes in
both directions. No buffering or protocol awareness — it's a dumb, fast pipe,
same as stunnel.

### Live cert reloads

If HFS's certificate file changes (renewal, manual replacement), this plugin
picks it up automatically and applies it to all running tunnels **without
dropping existing connections**. Only new TLS handshakes after the reload see
the refreshed certificate — anyone already connected (e.g. mid-stream on a
media server) is left alone.

### Config changes are scoped

Editing the tunnel list only affects the tunnels you actually changed. Adding
a new tunnel, removing one, or changing its target/listen settings restarts
just that tunnel. Tunnels you didn't touch, and their active connections,
are left running.

The one exception: if you change HFS's own `cert`/`private_key` **paths**
(not just their contents), all tunnels restart, since that's a wholesale
identity change rather than a routine renewal.

### Mutual TLS (optional)

By default this plugin behaves like plain TLS termination: it encrypts the
connection, but anything that can reach the listen port can talk to the
backend. There's no authentication beyond "can you complete a TLS handshake."

If you want to restrict access to clients holding a specific certificate,
set **Client CA cert path** on a tunnel to the path of a CA certificate.
Connections without a valid client certificate signed by that CA will be
rejected at the TLS layer, before any bytes reach your backend. This is
per-tunnel — you can leave some tunnels open and lock down others.

Generating client certificates and a CA is outside the scope of this plugin;
any standard `openssl` CA setup works.

## Things to know before relying on this

- **TLS termination is not access control** unless you configure a client
  CA. Anyone who can route to the listen port can reach the backend. If you
  need IP allowlisting or auth beyond mTLS, put a firewall rule in front of
  it too.
- **A cert renewal doesn't drop connections; most tunnel-config edits don't
  either** — only the specific tunnel(s) you actually change get restarted,
  and even then, only that tunnel's current connections are closed.
- **Backend connection timeout is 5 seconds.** If the backend doesn't accept
  the connection in that window, the client's TLS socket is closed.
- **No protocol inspection.** This is a raw byte pipe — it doesn't know or
  care what's flowing through it (HTTP, RTSP, whatever your backend speaks).
- **Port conflicts are logged, not retried.** If a listen port is already in
  use by something else, you'll see an error in the HFS log; the plugin
  won't keep retrying on its own — fix the conflict and re-save the config.

## Uninstall / disable

Set `disabled: true` on individual tunnel rows to turn them off, or remove
the plugin from the `plugins` directory entirely. Unloading the plugin closes
every listener and active connection cleanly.
