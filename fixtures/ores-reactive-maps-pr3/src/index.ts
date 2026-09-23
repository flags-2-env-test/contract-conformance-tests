export const DEFAULT_PUBLIC_PREFIX = "ORES_PUBLIC_";
export const RUNTIME_LAYER = "__runtime";
export const RUNTIME_PRIORITY = 1_000_000;

export type Visibility = boolean | undefined;
export type StringKey<TShape extends object> = Extract<keyof TShape, string>;
export type ValueOf<TShape extends object> = TShape[StringKey<TShape>];

export interface EntryInput<TValue = string> {
  value: TValue;
  public?: boolean;
}

export interface ResolvedEntry<TValue = string> {
  value: TValue;
  source: string;
  public: boolean;
  layer: string;
}

export type ChangeEvent<TShape extends object = Record<string, string>> = {
  [K in StringKey<TShape>]: {
    key: K;
    oldEntry?: ResolvedEntry<TShape[K]>;
    newEntry?: ResolvedEntry<TShape[K]>;
    revision: number;
  }
}[StringKey<TShape>];

export interface LayerInfo {
  name: string;
  source: string;
  priority: number;
  order: number;
  size: number;
}

export type Subscriber<TShape extends object = Record<string, string>> = (event: ChangeEvent<TShape>) => void;
export type LayerObject<TShape extends object> = Readonly<Partial<{
  [K in StringKey<TShape>]: TShape[K] | EntryInput<TShape[K]>;
}>>;
export type LayerValues<TShape extends object = Record<string, string>> =
  | LayerObject<TShape>
  | ReadonlyMap<StringKey<TShape>, ValueOf<TShape> | EntryInput<ValueOf<TShape>>>;

interface RawEntry {
  value: unknown;
  publicOverride?: boolean;
}

interface Layer {
  name: string;
  source: string;
  priority: number;
  order: number;
  entries: Map<string, RawEntry>;
}

function cloneResolved<TValue>(entry: ResolvedEntry<TValue> | undefined): ResolvedEntry<TValue> | undefined {
  return entry ? { ...entry } : undefined;
}

function sameEntry(a: ResolvedEntry<unknown> | undefined, b: ResolvedEntry<unknown> | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return a.value === b.value && a.source === b.source && a.public === b.public && a.layer === b.layer;
}

function ownObject<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

function iterableValues<TShape extends object>(
  values: LayerValues<TShape>,
): Iterable<[string, ValueOf<TShape> | EntryInput<ValueOf<TShape>>]> {
  if (values instanceof Map) {
    return values.entries() as Iterable<[string, ValueOf<TShape> | EntryInput<ValueOf<TShape>>]>;
  }
  return Object.entries(values) as Iterable<[string, ValueOf<TShape> | EntryInput<ValueOf<TShape>>]>;
}

function isEntryInput(value: unknown): value is EntryInput<unknown> {
  if (typeof value !== "object" || value === null || !("value" in value)) return false;
  if ("public" in value) return typeof (value as { public?: unknown }).public === "boolean";
  return typeof (value as { value?: unknown }).value === "string";
}

function normalizeRaw(value: unknown): RawEntry {
  if (!isEntryInput(value)) return { value };
  return value.public === undefined
    ? { value: value.value }
    : { value: value.value, publicOverride: value.public };
}

export class ReactiveMap<TShape extends object = Record<string, string>> {
  #layers = new Map<string, Layer>();
  #publicPrefix: string;
  #revision = 0;
  #nextLayerOrder = 0;
  #nextSubscription = 1;
  #subscribers = new Map<number, Subscriber<TShape>>();

  constructor(publicPrefix = DEFAULT_PUBLIC_PREFIX) {
    this.#publicPrefix = publicPrefix;
  }

  get revision(): number { return this.#revision; }
  get publicPrefix(): string { return this.#publicPrefix; }

  getVal<K extends StringKey<TShape>>(key: K): TShape[K] | undefined {
    return this.#resolve(key)?.value as TShape[K] | undefined;
  }

  getEntry<K extends StringKey<TShape>>(key: K): ResolvedEntry<TShape[K]> | undefined {
    return cloneResolved(this.#resolve(key) as ResolvedEntry<TShape[K]> | undefined);
  }

  getAllEntries(): Partial<{ [K in StringKey<TShape>]: ResolvedEntry<TShape[K]> }> {
    return this.#snapshot() as Partial<{ [K in StringKey<TShape>]: ResolvedEntry<TShape[K]> }>;
  }

  getPublicEntries(): Partial<{ [K in StringKey<TShape>]: ResolvedEntry<TShape[K]> }> {
    return this.#filterEntries(true) as Partial<{ [K in StringKey<TShape>]: ResolvedEntry<TShape[K]> }>;
  }

  getPrivateEntries(): Partial<{ [K in StringKey<TShape>]: ResolvedEntry<TShape[K]> }> {
    return this.#filterEntries(false) as Partial<{ [K in StringKey<TShape>]: ResolvedEntry<TShape[K]> }>;
  }

  setVal<K extends StringKey<TShape>>(key: K, value: TShape[K], isPublic?: boolean): void {
    this.#mutate(() => {
      this.#ensureLayer(RUNTIME_LAYER, "runtime", RUNTIME_PRIORITY);
      const layer = this.#layers.get(RUNTIME_LAYER)!;
      layer.source = "runtime";
      layer.priority = RUNTIME_PRIORITY;
      layer.entries.set(key, isPublic === undefined ? { value } : { value, publicOverride: isPublic });
    });
  }

  setValInLayer<K extends StringKey<TShape>>(layerName: string, key: K, value: TShape[K], isPublic?: boolean): void {
    const layer = this.#layers.get(layerName);
    if (!layer) throw new Error(`unknown layer: ${layerName}`);
    this.#mutate(() => {
      layer.entries.set(key, isPublic === undefined ? { value } : { value, publicOverride: isPublic });
    });
  }

  replaceLayer(name: string, source: string, priority: number, values: LayerValues<TShape>): void {
    this.#mutate(() => {
      const existing = this.#layers.get(name);
      const order = existing?.order ?? this.#nextLayerOrder++;
      const entries = new Map<string, RawEntry>();
      for (const [key, value] of iterableValues(values)) entries.set(key, normalizeRaw(value));
      this.#layers.set(name, { name, source, priority, order, entries });
    });
  }

  patchLayer(name: string, source: string, priority: number, values: LayerValues<TShape>): void {
    this.#mutate(() => {
      let layer = this.#layers.get(name);
      if (!layer) {
        layer = { name, source, priority, order: this.#nextLayerOrder++, entries: new Map() };
        this.#layers.set(name, layer);
      } else {
        layer.source = source;
        layer.priority = priority;
      }
      for (const [key, value] of iterableValues(values)) layer.entries.set(key, normalizeRaw(value));
    });
  }

  removeFromLayer<K extends StringKey<TShape>>(layerName: string, key: K): boolean {
    const layer = this.#layers.get(layerName);
    if (!layer || !layer.entries.has(key)) return false;
    this.#mutate(() => { layer.entries.delete(key); });
    return true;
  }

  removeLayer(layerName: string): boolean {
    if (!this.#layers.has(layerName)) return false;
    this.#mutate(() => { this.#layers.delete(layerName); });
    return true;
  }

  setLayerPriority(layerName: string, priority: number): void {
    const layer = this.#layers.get(layerName);
    if (!layer) throw new Error(`unknown layer: ${layerName}`);
    this.#mutate(() => { layer.priority = priority; });
  }

  setPublicPrefix(prefix: string): void {
    if (prefix === this.#publicPrefix) return;
    this.#mutate(() => { this.#publicPrefix = prefix; });
  }

  getLayerOrder(): LayerInfo[] {
    return [...this.#layers.values()]
      .sort((a, b) => a.priority - b.priority || a.order - b.order)
      .map((layer) => ({
        name: layer.name,
        source: layer.source,
        priority: layer.priority,
        order: layer.order,
        size: layer.entries.size,
      }));
  }

  subscribe(subscriber: Subscriber<TShape>): number {
    const id = this.#nextSubscription++;
    this.#subscribers.set(id, subscriber);
    return id;
  }

  unsubscribe(id: number): boolean { return this.#subscribers.delete(id); }

  #ensureLayer(name: string, source: string, priority: number): void {
    if (!this.#layers.has(name)) {
      this.#layers.set(name, { name, source, priority, order: this.#nextLayerOrder++, entries: new Map() });
    }
  }

  #isPublic(key: string, raw: RawEntry): boolean {
    return raw.publicOverride ?? key.startsWith(this.#publicPrefix);
  }

  #resolve(key: string): ResolvedEntry<unknown> | undefined {
    let winner: Layer | undefined;
    let raw: RawEntry | undefined;
    for (const layer of this.#layers.values()) {
      const candidate = layer.entries.get(key);
      if (!candidate) continue;
      if (!winner || layer.priority > winner.priority || (layer.priority === winner.priority && layer.order > winner.order)) {
        winner = layer;
        raw = candidate;
      }
    }
    if (!winner || !raw) return undefined;
    return { value: raw.value, source: winner.source, public: this.#isPublic(key, raw), layer: winner.name };
  }

  #snapshot(): Record<string, ResolvedEntry<unknown>> {
    const out = ownObject<ResolvedEntry<unknown>>();
    const keys = new Set<string>();
    for (const layer of this.#layers.values()) for (const key of layer.entries.keys()) keys.add(key);
    for (const key of [...keys].sort()) {
      const entry = this.#resolve(key);
      if (entry) out[key] = entry;
    }
    return out;
  }

  #filterEntries(isPublic: boolean): Record<string, ResolvedEntry<unknown>> {
    const out = ownObject<ResolvedEntry<unknown>>();
    for (const [key, entry] of Object.entries(this.#snapshot())) if (entry.public === isPublic) out[key] = entry;
    return out;
  }

  #mutate(change: () => void): void {
    const before = this.#snapshot();
    change();
    const after = this.#snapshot();
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
    const changed = [...keys].sort().filter((key) => !sameEntry(before[key], after[key]));
    if (changed.length === 0) return;

    this.#revision += 1;
    const revision = this.#revision;
    const subscribers = [...this.#subscribers.values()];
    for (const key of changed) {
      const oldEntry = cloneResolved(before[key]);
      const newEntry = cloneResolved(after[key]);
      const event = { key, revision } as ChangeEvent<TShape>;
      if (oldEntry !== undefined) (event as { oldEntry?: ResolvedEntry<unknown> }).oldEntry = oldEntry;
      if (newEntry !== undefined) (event as { newEntry?: ResolvedEntry<unknown> }).newEntry = newEntry;
      for (const subscriber of subscribers) subscriber(event);
    }
  }
}
