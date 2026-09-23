import { ReactiveMap } from "../src/index.js";

interface TypedCliConfig {
  PORT: number;
  DEBUG: boolean;
  TAGS: string[];
  RETRIES: number[];
  MATRIX: number[][];
  META: { value: number; label: string };
}

const map = new ReactiveMap<TypedCliConfig>();
map.replaceLayer("flags2env", "flags2env", 100, {
  PORT: 8080,
  DEBUG: false,
  TAGS: ["alpha", "beta"],
  RETRIES: [1, 2, 3],
  MATRIX: [[1, 2], [3, 4]],
  META: { value: 42, label: "answer" },
});

const port: number | undefined = map.getVal("PORT");
const debug: boolean | undefined = map.getVal("DEBUG");
const matrix: number[][] | undefined = map.getVal("MATRIX");
const meta: { value: number; label: string } | undefined = map.getVal("META");
void port;
void debug;
void matrix;
void meta;

map.setVal("DEBUG", true);

// @ts-expect-error unknown keys are rejected for an exact shape
map.getVal("NOT_DECLARED");
// @ts-expect-error value type follows the selected key
map.setVal("PORT", "8080");
