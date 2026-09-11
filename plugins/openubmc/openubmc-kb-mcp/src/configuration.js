import { constants } from 'node:fs';
import { open, lstat } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

function invalid() {
  return Object.assign(new Error('Invalid local KB configuration; check the private configuration and activate a valid revision.'), { code: 'KB_CONFIGURATION_INVALID' });
}

export async function readConfigurationJson(path, { privateFile = false, missing = false } = {}) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
    const info = await file.stat();
    if (!info.isFile() || info.size > 1024 * 1024 || (privateFile && process.platform !== 'win32'
      && (info.uid !== process.getuid() || (info.mode & 0o077)))) throw invalid();
    const bytes = Buffer.alloc(1024 * 1024 + 1);
    let size = 0;
    while (size < bytes.length) {
      const read = await file.read(bytes, size, bytes.length - size, null);
      if (!read.bytesRead) break;
      size += read.bytesRead;
    }
    if (size > 1024 * 1024) throw invalid();
    const value = JSON.parse(bytes.subarray(0, size).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
    return value;
  } catch (error) {
    if (missing && error.code === 'ENOENT') return null;
    throw invalid();
  } finally {
    await file?.close();
  }
}

export async function activeConfiguration(source) {
  const marker = await readConfigurationJson(join(dirname(source), `.${basename(source)}.active.json`), { privateFile: true, missing: true });
  if (marker === null) return { path: source, revision: null };
  if (marker.schema !== 'openubmc.configuration.v1' || typeof marker.revision !== 'string'
    || !/^[a-f0-9]{32}$/.test(marker.revision)) throw invalid();
  const directory = join(dirname(source), `.${basename(source)}.revisions`);
  try {
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32'
      && (info.uid !== process.getuid() || (info.mode & 0o077)))) throw invalid();
  } catch { throw invalid(); }
  return { path: join(directory, `${marker.revision}.json`), revision: marker.revision };
}
