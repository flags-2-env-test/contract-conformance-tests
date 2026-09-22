export const DEFAULT_PUBLIC_PREFIX = "ORES_PUBLIC_";
export const RUNTIME_LAYER = "__runtime";
export const RUNTIME_PRIORITY = 1_000_000;

export type Visibility = boolean | undefined;

export interface EntryInput {
  value: string;
  public?: boolean;
}

export interface ResolvedEntry {
  value: string;
  source: string;
  public: boolean;
  layer: string;
}

export interface ChangeEvent {
  key: string;
  oldEntry?: ResolvedEntry;
  newEntry?: ResolvedEntry;
  revision: number;
}

export interface LayerInfo {
  name: string;
  source: string;
  priority: number;
  order: number;
  size: number;
}

export type Subscriber = (event: ChangeEvent) => void;
export type LayerValues = Readonly<Record<string, string | EntryInput>> | ReadonlyMap<string, string | EntryInput>;

interface RawEntry {
  value: string;
  publicOverride?: boolean;
}

interface Layer {
  name: string;
  source: string;
  priority: number;
  order: number;
  entries: Map<string, RawEntry>;
}

function cloneResolved(entry: ResolvedEntry | undefined): ResolvedEntry | undefined {
  return entry ? { ...entry } : undefined;
}

function sameEntry(a: ResolvedEntry | undefined, b: ResolvedEntry | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return a.value === b.value && a.source === b.source && a.public === b.public && a.layer === b.layer;
}

function ownObject<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

function iterableValues(values: LayerValues): Iterable<[string, string | EntryInput]> {
  if (values instanceof Map) return values.entries();
  return Object.entries(values);
}

function normalizeRaw(value: string | EntryInput): RawEntry {
  if (typeof value === "string") return { value };
  return value.public === undefined
    ? { value: value.value }
    : { value: value.value, publicOverride: value.public };
}

export class ReactiveMap {
  #layers = new Map<string, Layer>();
  #publicPrefix: string;
  #revision = 0;
  #nextLayerOrder = 0;
  #nextSubscription = 1;
  #subscribers = new Map<number, Subscriber>();

  constructor(publicPrefix = DEFAULT_PUBLIC_PREFIX) { this.#publicPrefix = publicPrefix; }
  get revision(): number { return this.#revision; }
  get publicPrefix(): string { return this.#publicPrefix; }
  getVal(key: string): string | undefined { return this.#resolve(key)?.value; }
  getEntry(key: string): ResolvedEntry | undefined { return cloneResolved(this.#resolve(key)); }
  getAllEntries(): Record<string, ResolvedEntry> { return this.#snapshot(); }
  getPublicEntries(): Record<string, ResolvedEntry> { return this.#filterEntries(true); }
  getPrivateEntries(): Record<string, ResolvedEntry> { return this.#filterEntries(false); }

  setVal(key: string, value: string, isPublic?: boolean): void {
    this.#mutate(() => {
      this.#ensureLayer(RUNTIME_LAYER, "runtime", RUNTIME_PRIORITY);
      const layer = this.#layers.get(RUNTIME_LAYER)!;
      layer.entries.set(key, isPublic === undefined ? { value } : { value, publicOverride: isPublic });
    });
  }

  setValInLayer(layerName: string, key: string, value: string, isPublic?: boolean): void {
    const layer = this.#layers.get(layerName);
    if (!layer) throw new Error(`unknown layer: ${layerName}`);
    this.#mutate(() => { layer.entries.set(key, isPublic === undefined ? { value } : { value, publicOverride: isPublic }); });
  }

  replaceLayer(name: string, source: string, priority: number, values: LayerValues): void {
    this.#mutate(() => {
      const existing = this.#layers.get(name);
      const order = existing?.order ?? this.#nextLayerOrder++;
      const entries = new Map<string, RawEntry>();
      for (const [key, value] of iterableValues(values)) entries.set(key, normalizeRaw(value));
      this.#layers.set(name, { name, source, priority, order, entries });
    });
  }

  patchLayer(name: string, source: string, priority: number, values: LayerValues): void {
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

  removeFromLayer(layerName: string, key: string): boolean {
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
      .map((layer) => ({ name: layer.name, source: layer.source, priority: layer.priority, order: layer.order, size: layer.entries.size }));
  }

  subscribe(subscriber: Subscriber): number {
    const id = this.#nextSubscription++;
    this.#subscribers.set(id, subscriber);
    return id;
  }
  unsubscribe(id: number): boolean { return this.#subscribers.delete(id); }

  #ensureLayer(name: string, source: string, priority: number): void {
    if (!this.#layers.has(name)) this.#layers.set(name, { name, source, priority, order: this.#nextLayerOrder++, entries: new Map() });
  }
  #isPublic(key: string, raw: RawEntry): boolean { return raw.publicOverride ?? key.startsWith(this.#publicPrefix); }
  #resolve(key: string): ResolvedEntry | undefined {
    let winner: Layer | undefined;
    let raw: RawEntry | undefined;
    for (const layer of this.#layers.values()) {
      const candidate = layer.entries.get(key);
      if (!candidate) continue;
      if (!winner || layer.priority > winner.priority || (layer.priority === winner.priority && layer.order > winner.order)) { winner = layer; raw = candidate; }
    }
    if (!winner || !raw) return undefined;
    return { value: raw.value, source: winner.source, public: this.#isPublic(key, raw), layer: winner.name };
  }
  #snapshot(): Record<string, ResolvedEntry> {
    const out = ownObject<ResolvedEntry>();
    const keys = new Set<string>();
    for (const layer of this.#layers.values()) for (const key of layer.entries.keys()) keys.add(key);
    for (const key of [...keys].sort()) { const entry = this.#resolve(key); if (entry) out[key] = entry; }
    return out;
  }
  #filterEntries(isPublic: boolean): Record<string, ResolvedEntry> {
    const out = ownObject<ResolvedEntry>();
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
      const event: ChangeEvent = { key, revision };
      if (oldEntry !== undefined) event.oldEntry = oldEntry;
      if (newEntry !== undefined) event.newEntry = newEntry;
      for (const subscriber of subscribers) subscriber(event);
    }
  }
}
