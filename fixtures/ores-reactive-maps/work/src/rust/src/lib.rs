use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

pub const DEFAULT_PUBLIC_PREFIX: &str = "ORES_PUBLIC_";
pub const RUNTIME_LAYER: &str = "__runtime";
pub const RUNTIME_PRIORITY: i64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInput {
    pub value: String,
    pub public: Option<bool>,
}

impl EntryInput {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), public: None }
    }

    #[must_use]
    pub fn with_public(value: impl Into<String>, public: bool) -> Self {
        Self { value: value.into(), public: Some(public) }
    }
}

impl From<String> for EntryInput {
    fn from(value: String) -> Self { Self::new(value) }
}

impl From<&str> for EntryInput {
    fn from(value: &str) -> Self { Self::new(value) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEntry {
    pub value: String,
    pub source: String,
    pub is_public: bool,
    pub layer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEvent {
    pub key: String,
    pub old_entry: Option<ResolvedEntry>,
    pub new_entry: Option<ResolvedEntry>,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerInfo {
    pub name: String,
    pub source: String,
    pub priority: i64,
    pub order: u64,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawEntry {
    value: String,
    public_override: Option<bool>,
}

#[derive(Debug, Clone)]
struct Layer {
    name: String,
    source: String,
    priority: i64,
    order: u64,
    entries: BTreeMap<String, RawEntry>,
}

type Subscriber = Arc<dyn Fn(ChangeEvent) + Send + Sync + 'static>;

struct State {
    layers: BTreeMap<String, Layer>,
    public_prefix: String,
    revision: u64,
    next_layer_order: u64,
    next_subscription: u64,
    subscribers: BTreeMap<u64, Subscriber>,
}

impl State {
    fn new(public_prefix: impl Into<String>) -> Self {
        Self {
            layers: BTreeMap::new(),
            public_prefix: public_prefix.into(),
            revision: 0,
            next_layer_order: 0,
            next_subscription: 1,
            subscribers: BTreeMap::new(),
        }
    }

    fn resolve(&self, key: &str) -> Option<ResolvedEntry> {
        let mut winner: Option<(&Layer, &RawEntry)> = None;
        for layer in self.layers.values() {
            let Some(candidate) = layer.entries.get(key) else { continue; };
            let replace = match winner {
                None => true,
                Some((current, _)) => {
                    layer.priority > current.priority
                        || (layer.priority == current.priority && layer.order > current.order)
                }
            };
            if replace { winner = Some((layer, candidate)); }
        }
        let (layer, raw) = winner?;
        let is_public = raw
            .public_override
            .unwrap_or_else(|| key.starts_with(&self.public_prefix));
        Some(ResolvedEntry {
            value: raw.value.clone(),
            source: layer.source.clone(),
            is_public,
            layer: layer.name.clone(),
        })
    }

    fn snapshot(&self) -> BTreeMap<String, ResolvedEntry> {
        let mut keys = BTreeSet::new();
        for layer in self.layers.values() { keys.extend(layer.entries.keys().cloned()); }
        keys.into_iter()
            .filter_map(|key| self.resolve(&key).map(|entry| (key, entry)))
            .collect()
    }
}

#[derive(Clone)]
pub struct ReactiveMap {
    state: Arc<Mutex<State>>,
}

impl Default for ReactiveMap {
    fn default() -> Self { Self::new() }
}

impl ReactiveMap {
    #[must_use]
    pub fn new() -> Self { Self::with_public_prefix(DEFAULT_PUBLIC_PREFIX) }

    #[must_use]
    pub fn with_public_prefix(prefix: impl Into<String>) -> Self {
        Self { state: Arc::new(Mutex::new(State::new(prefix))) }
    }

    #[must_use]
    pub fn revision(&self) -> u64 { self.lock().revision }

    #[must_use]
    pub fn public_prefix(&self) -> String { self.lock().public_prefix.clone() }

    #[must_use]
    pub fn get_val(&self, key: &str) -> Option<String> {
        self.lock().resolve(key).map(|entry| entry.value)
    }

    #[must_use]
    pub fn get_entry(&self, key: &str) -> Option<ResolvedEntry> { self.lock().resolve(key) }

    #[must_use]
    pub fn get_all_entries(&self) -> BTreeMap<String, ResolvedEntry> { self.lock().snapshot() }

    #[must_use]
    pub fn get_public_entries(&self) -> BTreeMap<String, ResolvedEntry> { self.filtered_entries(true) }

    #[must_use]
    pub fn get_private_entries(&self) -> BTreeMap<String, ResolvedEntry> { self.filtered_entries(false) }

    pub fn set_val(&self, key: impl Into<String>, value: impl Into<String>, public: Option<bool>) {
        let key = key.into();
        let value = value.into();
        self.mutate(move |state| {
            let order = match state.layers.get(RUNTIME_LAYER) {
                Some(layer) => layer.order,
                None => {
                    let order = state.next_layer_order;
                    state.next_layer_order += 1;
                    order
                }
            };
            let layer = state.layers.entry(RUNTIME_LAYER.to_string()).or_insert_with(|| Layer {
                name: RUNTIME_LAYER.to_string(),
                source: "runtime".to_string(),
                priority: RUNTIME_PRIORITY,
                order,
                entries: BTreeMap::new(),
            });
            layer.source = "runtime".to_string();
            layer.priority = RUNTIME_PRIORITY;
            layer.entries.insert(key, RawEntry { value, public_override: public });
        });
    }

    pub fn set_val_in_layer(
        &self,
        layer_name: &str,
        key: impl Into<String>,
        value: impl Into<String>,
        public: Option<bool>,
    ) -> Result<(), String> {
        let layer_name = layer_name.to_string();
        let key = key.into();
        let value = value.into();
        self.mutate(move |state| {
            let Some(layer) = state.layers.get_mut(&layer_name) else {
                return Err(format!("unknown layer: {layer_name}"));
            };
            layer.entries.insert(key, RawEntry { value, public_override: public });
            Ok(())
        })
    }

    pub fn replace_layer(
        &self,
        name: impl Into<String>,
        source: impl Into<String>,
        priority: i64,
        values: BTreeMap<String, EntryInput>,
    ) {
        let name = name.into();
        let source = source.into();
        self.mutate(move |state| {
            let order = match state.layers.get(&name) {
                Some(layer) => layer.order,
                None => {
                    let order = state.next_layer_order;
                    state.next_layer_order += 1;
                    order
                }
            };
            let entries = values.into_iter().map(|(key, input)| {
                (key, RawEntry { value: input.value, public_override: input.public })
            }).collect();
            state.layers.insert(name.clone(), Layer { name, source, priority, order, entries });
        });
    }

    pub fn replace_string_layer(
        &self,
        name: impl Into<String>,
        source: impl Into<String>,
        priority: i64,
        values: BTreeMap<String, String>,
    ) {
        self.replace_layer(
            name,
            source,
            priority,
            values.into_iter().map(|(key, value)| (key, EntryInput::new(value))).collect(),
        );
    }

    pub fn patch_layer(
        &self,
        name: impl Into<String>,
        source: impl Into<String>,
        priority: i64,
        values: BTreeMap<String, EntryInput>,
    ) {
        let name = name.into();
        let source = source.into();
        self.mutate(move |state| {
            if !state.layers.contains_key(&name) {
                let order = state.next_layer_order;
                state.next_layer_order += 1;
                state.layers.insert(name.clone(), Layer {
                    name: name.clone(),
                    source: source.clone(),
                    priority,
                    order,
                    entries: BTreeMap::new(),
                });
            }
            let layer = state.layers.get_mut(&name).expect("layer inserted");
            layer.source = source;
            layer.priority = priority;
            for (key, input) in values {
                layer.entries.insert(key, RawEntry { value: input.value, public_override: input.public });
            }
        });
    }

    pub fn patch_string_layer(
        &self,
        name: impl Into<String>,
        source: impl Into<String>,
        priority: i64,
        values: BTreeMap<String, String>,
    ) {
        self.patch_layer(
            name,
            source,
            priority,
            values.into_iter().map(|(key, value)| (key, EntryInput::new(value))).collect(),
        );
    }

    pub fn remove_from_layer(&self, layer_name: &str, key: &str) -> bool {
        let layer_name = layer_name.to_string();
        let key = key.to_string();
        self.mutate(move |state| {
            state.layers.get_mut(&layer_name)
                .and_then(|layer| layer.entries.remove(&key))
                .is_some()
        })
    }

    pub fn remove_layer(&self, layer_name: &str) -> bool {
        let layer_name = layer_name.to_string();
        self.mutate(move |state| state.layers.remove(&layer_name).is_some())
    }

    pub fn set_layer_priority(&self, layer_name: &str, priority: i64) -> Result<(), String> {
        let layer_name = layer_name.to_string();
        self.mutate(move |state| {
            let Some(layer) = state.layers.get_mut(&layer_name) else {
                return Err(format!("unknown layer: {layer_name}"));
            };
            layer.priority = priority;
            Ok(())
        })
    }

    pub fn set_public_prefix(&self, prefix: impl Into<String>) {
        let prefix = prefix.into();
        self.mutate(move |state| { state.public_prefix = prefix; });
    }

    #[must_use]
    pub fn get_layer_order(&self) -> Vec<LayerInfo> {
        let state = self.lock();
        let mut layers: Vec<_> = state.layers.values().map(|layer| LayerInfo {
            name: layer.name.clone(),
            source: layer.source.clone(),
            priority: layer.priority,
            order: layer.order,
            size: layer.entries.len(),
        }).collect();
        layers.sort_by_key(|layer| (layer.priority, layer.order));
        layers
    }

    pub fn subscribe<F>(&self, subscriber: F) -> u64
    where
        F: Fn(ChangeEvent) + Send + Sync + 'static,
    {
        let mut state = self.lock();
        let id = state.next_subscription;
        state.next_subscription += 1;
        state.subscribers.insert(id, Arc::new(subscriber));
        id
    }

    pub fn unsubscribe(&self, id: u64) -> bool { self.lock().subscribers.remove(&id).is_some() }

    fn filtered_entries(&self, public: bool) -> BTreeMap<String, ResolvedEntry> {
        self.lock().snapshot().into_iter()
            .filter(|(_, entry)| entry.is_public == public)
            .collect()
    }

    fn mutate<R>(&self, change: impl FnOnce(&mut State) -> R) -> R {
        let mut state = self.lock();
        let before = state.snapshot();
        let result = change(&mut state);
        let after = state.snapshot();
        let keys: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
        let changed: Vec<_> = keys.into_iter()
            .filter(|key| before.get(key) != after.get(key))
            .collect();

        if changed.is_empty() { return result; }

        state.revision += 1;
        let revision = state.revision;
        let subscribers: Vec<_> = state.subscribers.values().cloned().collect();
        let events: Vec<_> = changed.into_iter().map(|key| ChangeEvent {
            old_entry: before.get(&key).cloned(),
            new_entry: after.get(&key).cloned(),
            key,
            revision,
        }).collect();
        drop(state);

        for event in events {
            for subscriber in &subscribers { subscriber(event.clone()); }
        }
        result
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn precedence_reveal_and_shadowed_mutation() {
        let map = ReactiveMap::new();
        map.replace_string_layer(
            "env", "env", 100,
            BTreeMap::from([
                ("PORT".into(), "3000".into()),
                ("ORES_PUBLIC_ORIGIN".into(), "https://example.test".into()),
            ]),
        );
        map.replace_string_layer(
            "flags", "flags", 200,
            BTreeMap::from([("PORT".into(), "8080".into())]),
        );
        assert_eq!(map.get_val("PORT").as_deref(), Some("8080"));
        assert_eq!(map.get_entry("PORT").unwrap().source, "flags");
        assert!(map.get_public_entries().contains_key("ORES_PUBLIC_ORIGIN"));

        let event_count = Arc::new(AtomicUsize::new(0));
        let event_count_clone = Arc::clone(&event_count);
        map.subscribe(move |_| { event_count_clone.fetch_add(1, Ordering::SeqCst); });
        let before = map.revision();
        map.patch_string_layer(
            "env", "env", 100,
            BTreeMap::from([("PORT".into(), "3001".into())]),
        );
        assert_eq!(map.revision(), before);
        assert_eq!(event_count.load(Ordering::SeqCst), 0);

        assert!(map.remove_from_layer("flags", "PORT"));
        assert_eq!(map.get_val("PORT").as_deref(), Some("3001"));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn callbacks_run_outside_lock() {
        let map = ReactiveMap::new();
        map.replace_string_layer(
            "env", "env", 100,
            BTreeMap::from([("K".into(), "a".into())]),
        );
        let clone = map.clone();
        map.subscribe(move |_| { assert!(clone.get_val("K").is_some()); });
        map.patch_string_layer(
            "env", "env", 100,
            BTreeMap::from([("K".into(), "b".into())]),
        );
    }
}
