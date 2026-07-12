import assert from "node:assert/strict";
import http from "node:http";

import { MuninnClient } from "../dist/index.js";

let serveCurrent = false;
const server = http.createServer((_request, response) => {
  response.setHeader("content-type", "application/json");
  response.end(
    JSON.stringify(
      serveCurrent
        ? {
            engram_count: 8,
            vault_count: 1,
            stats_scope: "global",
            coherence: { alpha: { score: 0.8, total_engrams: 8 } },
          }
        : {
            vault: "legacy",
            total_engrams: 7,
            total_vaults: 3,
            coherence: { score: 0.5, issues: ["legacy"] },
          },
    ),
  );
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
if (address === null || typeof address === "string") {
  throw new Error("test server did not expose a TCP address");
}

const client = new MuninnClient({
  baseUrl: `http://127.0.0.1:${address.port}`,
  token: "test",
  defaultVault: "default",
});

try {
  const legacy = await client.stats();
  assert.equal(legacy.engram_count, 7);
  assert.equal(legacy.total_engrams, 7);
  assert.equal(legacy.vault, "legacy");
  assert.equal(legacy.stats_scope, "unknown");
  assert.equal(legacy.coherence?.score, 0.5);
  assert.deepEqual(legacy.coherence?.issues, ["legacy"]);

  serveCurrent = true;
  const current = await client.stats();
  assert.equal(current.engram_count, 8);
  assert.equal(current.total_engrams, 8);
  assert.equal(current.vault, "default");
  assert.equal(current.coherence?.score, 0.8);
  assert.deepEqual(current.coherence?.issues, []);
  assert.equal(current.coherence_by_vault?.alpha.total_engrams, 8);
} finally {
  client.close();
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

console.log("node current+legacy stats contracts passed");
