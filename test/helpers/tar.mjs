// Minimal USTAR + gzip encoder — just enough to fabricate npm tarballs for
// the mock registry. Hand-rolled so the test harness adds zero dependencies
// beyond vitest itself (same zero-dep principle as the binary under test).
import { gzipSync } from 'node:zlib';

const BLOCK = 512;

/**
 * Write one numeric tar header field as zero-padded octal + NUL.
 * @param {Buffer} buf - header block
 * @param {number} offset - field start
 * @param {number} len - field width
 * @param {number} value - numeric value to encode
 */
function octal(buf, offset, len, value) {
  buf.write(value.toString(8).padStart(len - 1, '0') + '\0', offset, 'ascii');
}

/**
 * Build one 512-byte USTAR header for a regular file.
 * @param {string} name - path inside the tarball (npm expects "package/...")
 * @param {number} size - file byte length
 * @returns {Buffer} header block
 */
function header(name, size) {
  const buf = Buffer.alloc(BLOCK);
  buf.write(name, 0, 'utf8');
  octal(buf, 100, 8, 0o644); // mode
  octal(buf, 108, 8, 0); // uid
  octal(buf, 116, 8, 0); // gid
  octal(buf, 124, 12, size);
  octal(buf, 136, 12, 0); // mtime: fixed for deterministic tarballs
  buf.write('        ', 148, 'ascii'); // chksum: spaces during computation
  buf.write('0', 156, 'ascii'); // typeflag: regular file
  buf.write('ustar\0' + '00', 257, 'ascii'); // magic + version
  let sum = 0;
  for (const b of buf) sum += b;
  buf.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'ascii');
  return buf;
}

/**
 * Create a gzipped npm package tarball from a map of file contents.
 * @param {Record<string, string>} files - path (without "package/") → content
 * @returns {Buffer} .tgz bytes ready to serve
 */
export function packTgz(files) {
  const parts = [];
  for (const [path, content] of Object.entries(files)) {
    const data = Buffer.from(content, 'utf8');
    parts.push(header('package/' + path, data.length), data);
    const pad = (BLOCK - (data.length % BLOCK)) % BLOCK;
    if (pad) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(BLOCK * 2)); // end-of-archive marker
  return gzipSync(Buffer.concat(parts), { mtime: 0 });
}
