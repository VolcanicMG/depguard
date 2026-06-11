// Mock npm registry — the deterministic stand-in for registry.npmjs.org.
//
// Lets each test fabricate packages with EXACT publish ages, which is the
// whole point: the cooldown filter can't be tested reliably against the real
// registry (real publish dates drift past the cutoff over time).
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { packTgz } from './tar.mjs';

export class MockRegistry {
  constructor() {
    /** @type {Map<string, object>} package name → packument */
    this.packuments = new Map();
    /** @type {Map<string, Buffer>} URL path → tarball bytes */
    this.tarballs = new Map();
    this.server = null;
    this.url = '';
  }

  /** Start serving on a random localhost port. */
  async start() {
    this.server = createServer((req, res) => this.#handle(req, res));
    await new Promise((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.url = `http://127.0.0.1:${this.server.address().port}`;
    return this;
  }

  /** Stop the server (call in afterAll). */
  async stop() {
    await new Promise((resolve) => this.server.close(resolve));
  }

  /**
   * Publish a fake package version with a controlled age.
   * @param {string} name - package name (scoped OK)
   * @param {string} version - exact version
   * @param {object} [opts]
   * @param {number} [opts.ageDays=100] - days since "publish" (cooldown input)
   * @param {Record<string,string>} [opts.scripts] - lifecycle scripts to declare
   * @param {Record<string,string>} [opts.files] - extra files in the tarball
   * @param {string} [opts.deprecated] - mark the version deprecated with this message
   */
  publish(name, version, { ageDays = 100, scripts = {}, files = {}, deprecated } = {}) {
    const manifest = { name, version, ...(Object.keys(scripts).length && { scripts }) };
    const tgz = packTgz({
      'package.json': JSON.stringify(manifest, null, 2),
      'index.js': `module.exports = '${name}@${version}';\n`,
      ...files,
    });
    // npm verifies dist.integrity against the bytes — compute the real ssri.
    const integrity = 'sha512-' + createHash('sha512').update(tgz).digest('base64');

    const base = name.includes('/') ? name.split('/')[1] : name;
    const tarPath = `/${name}/-/${base}-${version}.tgz`;
    this.tarballs.set(tarPath, tgz);

    let doc = this.packuments.get(name);
    if (!doc) {
      doc = { name, 'dist-tags': {}, versions: {}, time: { created: iso(3650) } };
      this.packuments.set(name, doc);
    }
    doc.versions[version] = {
      ...manifest,
      // Tarball URL points straight at the mock; depguard's proxy passes the
      // packument through and npm fetches the tarball from here.
      dist: { tarball: this.url + tarPath, integrity },
      ...(deprecated && { deprecated }),
    };
    doc.time[version] = iso(ageDays);
    doc.time.modified = iso(0);
    // Last publish wins `latest`, like the real registry default.
    doc['dist-tags'].latest = version;
  }

  /** @param {import('http').IncomingMessage} req @param {import('http').ServerResponse} res */
  #handle(req, res) {
    const path = decodeURIComponent(req.url.split('?')[0]);
    if (this.tarballs.has(path)) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(this.tarballs.get(path));
      return;
    }
    const name = path.replace(/^\//, '');
    if (this.packuments.has(name)) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(this.packuments.get(name)));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"Not found"}');
  }
}

/** ISO timestamp `days` days in the past. */
function iso(days) {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}
