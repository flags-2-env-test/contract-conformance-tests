import assert from "node:assert/strict";
import test from "node:test";
import { ReactiveMap } from "../src/index.ts";

test("layer precedence, reveal, provenance, visibility and events", () => {
  const map = new ReactiveMap();
  map.replaceLayer("env", "env", 100, {
    PORT: "3000",
    ORES_PUBLIC_ORIGIN: "https://example.test",
  });
  map.replaceLayer("flags", "flags", 200, { PORT: "8080" });
  assert.equal(map.getVal("PORT"), "8080");
  assert.deepEqual(map.getEntry("PORT"), { value: "8080", source: "flags", public: false, layer: "flags" });
  assert.equal(map.getPublicEntries().ORES_PUBLIC_ORIGIN?.value, "https://example.test");

  const events: string[] = [];
  map.subscribe((event) => events.push(`${event.revision}:${event.key}:${event.newEntry?.value ?? "<none>"}`));

  const before = map.revision;
  map.patchLayer("env", "env", 100, { PORT: "3001" });
  assert.equal(map.revision, before);
  assert.deepEqual(events, []);

  map.removeFromLayer("flags", "PORT");
  assert.equal(map.getVal("PORT"), "3001");
  assert.deepEqual(events, [`${before + 1}:PORT:3001`]);
});

test("runtime override and public prefix changes are reactive", () => {
  const map = new ReactiveMap();
  map.replaceLayer("env", "env", 100, { CLIENT_KEY: "x" });
  const events: string[] = [];
  map.subscribe((event) => events.push(event.key));

  map.setPublicPrefix("CLIENT_");
  assert.equal(map.getEntry("CLIENT_KEY")?.public, true);
  assert.deepEqual(events, ["CLIENT_KEY"]);

  map.setVal("CLIENT_KEY", "runtime", false);
  assert.deepEqual(map.getEntry("CLIENT_KEY"), { value: "runtime", source: "runtime", public: false, layer: "__runtime" });
});

test("equal priority uses layer creation order and replacement preserves order", () => {
  const map = new ReactiveMap();
  map.replaceLayer("a", "a", 10, { K: "a" });
  map.replaceLayer("b", "b", 10, { K: "b" });
  assert.equal(map.getVal("K"), "b");
  map.replaceLayer("a", "a2", 10, { K: "a2" });
  assert.equal(map.getVal("K"), "b");
  map.setLayerPriority("a", 11);
  assert.equal(map.getVal("K"), "a2");
});
