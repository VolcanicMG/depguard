// Mock PyPI — the PEP 691 Simple index (JSON v1) AND the JSON API that
// `guard check` reads publish times from, both off the same fabricated ages.
//
// Like registry.mjs, it fabricates EXACT upload ages so the cooldown filter is
// testable. By default file URLs point at a closed loopback port: pip resolves
// through guard's proxy, then fails to download — the test asserts on what the
// proxy hid, and nothing is ever installed. A release published with `files`
// is a REAL sdist (served here, real sha256) that pip and the box can build.
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { packTgz } from './tar.mjs';

export class MockPyPI {
  constructor() {
    /** @type {Map<string, {version: string, file: object}[]>} normalized name → releases' files */
    this.projects = new Map();
    /** @type {Map<string, Buffer>} filename → served sdist bytes */
    this.blobs = new Map();
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
   * @param {Record<string,string>} [opts.files] - sdist contents (implies sdist): served for real
   * @param {string} [opts.requiresPython] - the file's PEP 691 requires-python
   * @returns {MockPyPI} this, for chaining (call after start())
   */
  publish(name, version, { ageDays = 100, sdist = false, files, requiresPython } = {}) {
    const dist = name.replace(/-/g, '_');
    const isSdist = sdist || Boolean(files);
    const filename = isSdist ? `${dist}-${version}.tar.gz` : `${dist}-${version}-py3-none-any.whl`;
    let url = `http://127.0.0.1:9/files/${filename}`;
    let sha256 = '0'.repeat(64);
    if (files) {
      const blob = packTgz(files, `${dist}-${version}`);
      this.blobs.set(filename, blob);
      url = `${this.url}/files/${filename}`;
      sha256 = createHash('sha256').update(blob).digest('hex');
    }
    const entries = this.projects.get(name) ?? [];
    entries.push({
      version,
      file: {
        filename,
        url,
        hashes: { sha256 },
        'upload-time': new Date(Date.now() - ageDays * 86_400_000).toISOString(),
        ...(requiresPython && { 'requires-python': requiresPython }),
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
    let m = req.url.match(/^\/files\/([^/]+)$/);
    if (m && this.blobs.has(m[1])) {
      res.writeHead(200, { 'content-type': 'application/gzip' });
      res.end(this.blobs.get(m[1]));
      return;
    }
    m = req.url.match(/^\/simple\/([^/]+)\/$/);
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

/**
 * Files of a buildable sdist with an IN-TREE PEP 517 backend: `requires = []`
 * plus `backend-path = ["."]`, so building needs no build dependencies and no
 * network. backend.py writes a minimal wheel with only zipfile + hand-written
 * METADATA/WHEEL/RECORD. With `evil`, build_wheel first tries a TCP connect to
 * 203.0.113.1:80 (TEST-NET-3, unroutable — same as the demo) for the box to catch.
 * @param {string} name - project name (PEP 503-normalized)
 * @param {string} version - exact version
 * @param {object} [opts]
 * @param {boolean} [opts.evil=false] - phone home during build_wheel
 * @returns {Record<string,string>} sdist path → content
 */
export function inTreeSdist(name, version, { evil = false } = {}) {
  const dist = name.replace(/-/g, '_');
  const phoneHome = evil
    ? `    import socket
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("203.0.113.1", 80))
    except OSError:
        pass
`
    : '';
  return {
    'PKG-INFO': `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n`,
    'pyproject.toml': '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n',
    [`${dist}/__init__.py`]: 'VALUE = 1\n',
    'backend.py': `import base64, hashlib, os, zipfile

NAME, VER = "${dist}", "${version}"
DI = NAME + "-" + VER + ".dist-info"


def _files():
    return {
        NAME + "/__init__.py": b"VALUE = 1\\n",
        DI + "/METADATA": ("Metadata-Version: 2.1\\nName: ${name}\\nVersion: " + VER + "\\n").encode(),
        DI + "/WHEEL": b"Wheel-Version: 1.0\\nGenerator: guard-test\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
    }


def _record(files):
    lines = []
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        lines.append(path + ",sha256=" + digest + "," + str(len(data)))
    lines.append(DI + "/RECORD,,")
    return ("\\n".join(lines) + "\\n").encode()


def get_requires_for_build_wheel(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    os.makedirs(os.path.join(metadata_directory, DI), exist_ok=True)
    for path, data in _files().items():
        if path.startswith(DI):
            with open(os.path.join(metadata_directory, path), "wb") as f:
                f.write(data)
    return DI


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
${phoneHome}    name = NAME + "-" + VER + "-py3-none-any.whl"
    files = _files()
    with zipfile.ZipFile(os.path.join(wheel_directory, name), "w") as z:
        for path, data in files.items():
            z.writestr(path, data)
        z.writestr(DI + "/RECORD", _record(files))
    return name
`,
  };
}
