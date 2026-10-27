import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after } from "node:test";

const roots = [];
export async function privateFixtureDirectory(prefix) {
  const root = await mkdtemp(join(tmpdir(), prefix));
  roots.push(root);
  return root;
}
export async function writePrivateFixture(path, content) {
  await writeFile(path, content, { mode: 0o600 });
}
after(async () => {
  for (const root of roots.reverse()) await rm(root, { recursive: true, force: true });
});
