// hfs-tls-tunnel — stunnel-like TLS front-end for one or more local plaintext
// services, all reusing the same certificate/key that HFS itself is configured with.
//
// Install: copy this folder into HFS's `plugins` directory (next to config.yaml),
// or during development just create it directly inside `.hfs/plugins/hfs-tls-tunnel/`.
//
// Requires HFS to already have `cert` and `private_key` set in its config
// (Admin panel > HTTPS, or config.yaml).

const fs = require('fs')
const tls = require('tls')
const net = require('net')

exports.description = "Wrap one or more local plaintext TCP services in TLS using HFS's own certificate (stunnel-style)."
exports.version = 3
exports.apiRequired = 12.3

exports.config = {
  tunnels: {
    type: 'array',
    helperText: 'Each row opens its own TLS listener that forwards decrypted traffic to a plaintext backend.',
    fields: {
      listen_host: { type: 'string', label: 'Listen address', defaultValue: '0.0.0.0', helperText: '0.0.0.0 accepts connections on all interfaces/IPs. Set to a specific local IP to bind this tunnel to just that interface.', $width: 6 },
      listen_port: { type: 'number', label: 'Listen port (TLS)', $width: 6 },
      target_host: { type: 'string', label: 'Backend host', defaultValue: '127.0.0.1', $width: 6 },
      target_port: { type: 'number', label: 'Backend port (plain)', $width: 6 },
      client_ca: { type: 'string', label: 'Client CA cert path (optional)', helperText: 'If set, connecting clients must present a certificate signed by this CA (mutual TLS). Leave blank for plain TLS (default).', $width: 8 },
      disabled: { type: 'boolean', label: 'Disabled', $width: 4 },
    },
  },
}

exports.init = function (api) {
  const servers = new Map() // listen_port -> tls.Server
  let certWatchers = []
  let restartTimer
  let lastTunnels = [] // previous tunnel configs, used to diff on updates

  function readBaseCert() {
    const certPath = api.getHfsConfig('cert')
    const keyPath = api.getHfsConfig('private_key')
    if (!certPath || !keyPath) {
      api.log('no cert/private_key configured in HFS — cannot start TLS tunnels')
      return null
    }
    try {
      return { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }
    } catch (e) {
      api.log('failed reading cert/key files:', e.message)
      return null
    }
  }

  // builds full tls.createServer() options for one tunnel, optionally adding
  // mutual-TLS (client cert) requirements if the tunnel has client_ca set
  function buildTlsOptions(base, tunnelCfg) {
    const opts = { ...base }
    if (tunnelCfg && tunnelCfg.client_ca) {
      try {
        opts.ca = fs.readFileSync(tunnelCfg.client_ca)
        opts.requestCert = true
        opts.rejectUnauthorized = true
      } catch (e) {
        api.log(`tunnel :${tunnelCfg.listen_port} — failed reading client_ca, refusing to start without it:`, e.message)
        return null
      }
    }
    return opts
  }

  function sameTunnelConfig(a, b) {
    return a && b &&
      a.listen_host === b.listen_host &&
      a.target_host === b.target_host &&
      a.target_port === b.target_port &&
      a.client_ca === b.client_ca
  }

  function stopOne(listen_port) {
    const server = servers.get(listen_port)
    if (!server) return
    // server.close() alone only stops accepting *new* connections — any
    // clients already connected (from any IP) would otherwise be left
    // running against the old TLS context after a cert rotation or
    // config change. Force-close every tracked socket too.
    for (const sock of server.__sockets) sock.destroy()
    server.close()
    servers.delete(listen_port)
  }

  function stopAll() {
    for (const port of [...servers.keys()]) stopOne(port)
  }

  function startOne(tlsOptions, tunnelCfg) {
    const { listen_host, listen_port, target_host, target_port } = tunnelCfg
    const server = tls.createServer(tlsOptions, tlsSocket => {
      server.__sockets.add(tlsSocket)
      const backend = net.connect(target_port, target_host)
      backend.setTimeout(5000, () => {
        api.log(`tunnel :${listen_port} — backend ${target_host}:${target_port} connect timed out`)
        backend.destroy()
      })
      const cleanup = () => {
        server.__sockets.delete(tlsSocket)
        tlsSocket.destroy()
        backend.destroy()
      }
      backend.on('connect', () => {
        backend.setTimeout(0) // hand off to the pipes, no idle timeout on an active stream
        tlsSocket.pipe(backend)
        backend.pipe(tlsSocket)
      })
      tlsSocket.on('error', cleanup)
      backend.on('error', cleanup)
      tlsSocket.on('close', cleanup)
      backend.on('close', cleanup)
    })
    server.__sockets = new Set() // every concurrently-connected client, any IP
    server.on('error', e => api.log(`tunnel :${listen_port} error (port may already be in use):`, e.message))
    // omitting the host arg (undefined) binds all interfaces, same as before;
    // passing listen_host restricts this tunnel to one specific local IP
    server.listen(listen_port, listen_host || undefined, () =>
      api.log(`TLS tunnel: ${listen_host ? listen_host + ':' : ':'}${listen_port} -> ${target_host}:${target_port}${tunnelCfg.client_ca ? ' (mTLS)' : ''}`))
    servers.set(listen_port, server)
  }

  // Full (re)build — used on first load and whenever HFS's own cert/key paths
  // change (a wholesale identity change, not something worth diffing against).
  function startAll() {
    stopAll()
    const base = readBaseCert()
    if (!base) { lastTunnels = []; return }
    const { tunnels = [] } = api.getConfig()
    const seenPorts = new Set()
    const kept = []
    for (const t of tunnels) {
      if (t.disabled) continue
      if (!t.listen_port || !t.target_port) { api.log('skipping incomplete tunnel entry:', t); continue }
      if (t.target_port === t.listen_port && (t.target_host || '127.0.0.1') === (t.listen_host || '0.0.0.0')) {
        api.log(`skipping tunnel :${t.listen_port} — target is identical to listener, would loop`)
        continue
      }
      if (seenPorts.has(t.listen_port)) { api.log(`skipping duplicate listen_port ${t.listen_port}`); continue }
      seenPorts.add(t.listen_port)
      const tlsOptions = buildTlsOptions(base, t)
      if (!tlsOptions) continue
      startOne(tlsOptions, t)
      kept.push(t)
    }
    lastTunnels = kept
  }

  // Reload just the cert/key material onto already-running servers, in place.
  // Existing connections (and their sockets) are left completely alone —
  // only *new* TLS handshakes after this point see the refreshed cert.
  function reloadCertOnly() {
    const base = readBaseCert()
    if (!base) return
    if (servers.size === 0) { startAll(); return } // nothing running yet, do a full start instead
    for (const t of lastTunnels) {
      const server = servers.get(t.listen_port)
      if (!server) continue
      const tlsOptions = buildTlsOptions(base, t)
      if (!tlsOptions) continue
      server.setSecureContext(tlsOptions)
    }
    api.log(`reloaded TLS cert on ${servers.size} tunnel(s) without dropping connections`)
  }

  // Diff-based update: only tunnels that were added, removed, or had their
  // target/listen/client_ca settings changed get their sockets touched.
  // A tunnel nobody edited keeps every live connection running.
  function reconcileTunnels() {
    const base = readBaseCert()
    if (!base) { stopAll(); lastTunnels = []; return }
    const { tunnels = [] } = api.getConfig()
    const prevByPort = new Map(lastTunnels.map(t => [t.listen_port, t]))
    const seenPorts = new Set()
    const kept = []

    for (const t of tunnels) {
      if (t.disabled || !t.listen_port || !t.target_port) continue
      if (t.target_port === t.listen_port && (t.target_host || '127.0.0.1') === (t.listen_host || '0.0.0.0')) {
        api.log(`skipping tunnel :${t.listen_port} — target is identical to listener, would loop`)
        continue
      }
      if (seenPorts.has(t.listen_port)) { api.log(`skipping duplicate listen_port ${t.listen_port}`); continue }
      seenPorts.add(t.listen_port)

      const prev = prevByPort.get(t.listen_port)
      if (prev && sameTunnelConfig(prev, t) && servers.has(t.listen_port)) {
        kept.push(t) // unchanged — leave the running server + its sockets alone
        continue
      }

      // new tunnel, or an existing one whose settings changed: only this one restarts
      if (servers.has(t.listen_port)) stopOne(t.listen_port)
      const tlsOptions = buildTlsOptions(base, t)
      if (!tlsOptions) continue
      startOne(tlsOptions, t)
      kept.push(t)
    }

    // anything that used to exist but isn't in the new config anymore
    for (const port of [...servers.keys()])
      if (!seenPorts.has(port)) stopOne(port)

    lastTunnels = kept
  }

  function scheduleReconcile() {
    clearTimeout(restartTimer)
    restartTimer = setTimeout(reconcileTunnels, 300)
  }

  function watchCertFiles() {
    certWatchers.forEach(w => w.close())
    certWatchers = []
    const certPath = api.getHfsConfig('cert')
    const keyPath = api.getHfsConfig('private_key')
    for (const p of new Set([certPath, keyPath].filter(Boolean))) {
      try {
        certWatchers.push(fs.watch(p, { persistent: false }, reloadCertOnly))
      } catch (e) {
        api.log('could not watch cert file', p, e.message)
      }
    }
  }

  // tunnels list changed in config — reconcile without dropping unaffected connections
  const unsubOwnConfig = api.subscribeConfig('tunnels', scheduleReconcile)

  // HFS's cert/private_key *paths* changed — re-watch the new files and do a
  // full restart, since the underlying cert identity itself is changing wholesale
  const offCertPath = api.events.on('config.cert', () => { watchCertFiles(); startAll() })
  const offKeyPath = api.events.on('config.private_key', () => { watchCertFiles(); startAll() })

  watchCertFiles()
  startAll()

  return {
    unload() {
      stopAll()
      clearTimeout(restartTimer)
      unsubOwnConfig()
      offCertPath()
      offKeyPath()
      certWatchers.forEach(w => w.close())
    }
  }
}
