/**
 * fetch-stub.mjs — TEST-ONLY preload (`node --import`) that replaces the
 * global fetch so `bin/quant.mjs witness` runs fully offline. Used by
 * test/gossip-archive.test.mjs; never loaded by the engine itself.
 *
 * Routes come from the JSON file named by GOSSIP_STUB:
 *   listing     the observer's GitHub contents listing (array of items)
 *   bodies      { "<download_url>": route }, route is one of
 *                 { file, padTo? }  serve a file, optionally padded with
 *                                   JSON whitespace (0x20) to padTo bytes
 *                 { status }        answer that HTTP status (an outage)
 *                 { streamBytes }   stream that many bytes in 64 KiB chunks
 *   pulledFile  where the stream route records how many bytes the engine
 *               actually pulled (the read-bound evidence)
 * Every other URL (Rekor, the TSA authorities) answers 503, which those
 * passes already treat as an honest, counted gap.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const cfg = JSON.parse(readFileSync(process.env.GOSSIP_STUB, 'utf8'));
const LISTING_PREFIX = 'https://api.github.com/repos/szl-holdings/szl-quant-witness/contents/observations';
const CHUNK = 64 * 1024;

globalThis.fetch = async (input) => {
  const url = input instanceof Request ? input.url : String(input);
  if (url.startsWith(LISTING_PREFIX)) {
    return new Response(JSON.stringify(cfg.listing), { status: 200, headers: { 'content-type': 'application/json' } });
  }
  const route = cfg.bodies?.[url];
  if (!route) return new Response('fetch-stub: offline', { status: 503 });
  if (route.status) return new Response('fetch-stub: outage', { status: route.status });
  if (route.file) {
    let bytes = readFileSync(route.file);
    if (route.padTo > bytes.length) bytes = Buffer.concat([bytes, Buffer.alloc(route.padTo - bytes.length, 0x20)]);
    return new Response(bytes, { status: 200 });
  }
  let sent = 0;
  writeFileSync(cfg.pulledFile, '0');
  return new Response(new ReadableStream({
    pull(controller) {
      if (sent >= route.streamBytes) { controller.close(); return; }
      controller.enqueue(new Uint8Array(CHUNK).fill(0x20));
      sent += CHUNK;
      writeFileSync(cfg.pulledFile, String(sent));
    },
  }), { status: 200 });
};
