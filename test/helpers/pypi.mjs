// Mock PyPI — the PEP 691 Simple index (JSON v1) AND the JSON API that
// `guard check` reads publish times from, both off the same fabricated ages.
//
// Like registry.mjs, it fabricates EXACT upload ages so the cooldown filter is
// testable. File URLs point at a closed loopback port on purpose: pip resolves
// through guard's proxy, then fails to download — the test asserts on what the
// proxy hid, and nothing is ever installed.
import { createServer } from 'node:http';

export class MockPyPI {
  constructor() {
    /** @type {Map<string, {version: string, file: object}[]>} normalized name → releases' files */
    this.projects = new Map();
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
   * Publish a fake release with one pure-Python wheel (or an sdist).
   * @param {string} name - project name (PEP 503-normalized)
   * @param {string} version - exact version
   * @param {object} [opts]
   * @param {number} [opts.ageDays=100] - days since upload (cooldown input)
   * @param {boolean} [opts.sdist=false] - publish a .tar.gz instead of a wheel
   * @returns {MockPyPI} this, for chaining
   */
  publish(name, version, { ageDays = 100, sdist = false } = {}) {
    const dist = name.replace(/-/g, '_');
    const filename = sdist ? `${dist}-${version}.tar.gz` : `${dist}-${version}-py3-none-any.whl`;
    const entries = this.projects.get(name) ?? [];
    entries.push({
      version,
      file: {
        filename,
        url: `http://127.0.0.1:9/files/${filename}`,
        hashes: { sha256: '0'.repeat(64) },
        'upload-time': new Date(Date.now() - ageDays * 86_400_000).toISOString(),
      },
    });
    this.projects.set(name, entries);
    return this;
  }

  #handle(req, res) {
    const json = (body) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    let m = req.url.match(/^\/simple\/([^/]+)\/$/);
    if (m && this.projects.has(m[1])) {
      const entries = this.projects.get(m[1]);
      res.writeHead(200, { 'content-type': 'application/vnd.pypi.simple.v1+json' });
      res.end(JSON.stringify({
        meta: { 'api-version': '1.1' },
        name: m[1],
        files: entries.map((e) => e.file),
        versions: [...new Set(entries.map((e) => e.version))],
      }));
      return;
    }
    // JSON API: /pypi/<name>/json (all releases) and /pypi/<name>/<ver>/json.
    const urls = (es) => es.map((e) => ({ filename: e.file.filename, upload_time_iso_8601: e.file['upload-time'] }));
    m = req.url.match(/^\/pypi\/([^/]+)\/(?:([^/]+)\/)?json$/);
    const entries = m && this.projects.get(m[1]);
    if (entries && m[2]) {
      const rel = entries.filter((e) => e.version === m[2]);
      if (rel.length) return json({ urls: urls(rel) });
    } else if (entries) {
      const releases = {};
      for (const e of entries) (releases[e.version] ??= []).push(...urls([e]));
      return json({ releases });
    }
    res.writeHead(404).end();
  }
}
