import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/string

pub const default_public_prefix = "ORES_PUBLIC_"
pub const runtime_layer = "__runtime"
pub const runtime_priority = 1_000_000

pub type EntryInput {
  EntryInput(value: String, public: Option(Bool))
}

pub type ResolvedEntry {
  ResolvedEntry(
    value: String,
    source: String,
    is_public: Bool,
    layer: String,
  )
}

pub type ChangeEvent {
  ChangeEvent(
    key: String,
    old_entry: Option(ResolvedEntry),
    new_entry: Option(ResolvedEntry),
    revision: Int,
  )
}

pub type LayerInfo {
  LayerInfo(
    name: String,
    source: String,
    priority: Int,
    order: Int,
    size: Int,
  )
}

type RawEntry {
  RawEntry(value: String, public_override: Option(Bool))
}

type Layer {
  Layer(
    name: String,
    source: String,
    priority: Int,
    order: Int,
    entries: Dict(String, RawEntry),
  )
}

pub opaque type ReactiveMap {
  ReactiveMap(
    layers: Dict(String, Layer),
    public_prefix: String,
    revision_: Int,
    next_layer_order: Int,
    next_subscription: Int,
    subscribers: List(#(Int, fn(ChangeEvent) -> Nil)),
  )
}

pub fn new() -> ReactiveMap {
  with_public_prefix(default_public_prefix)
}

pub fn with_public_prefix(prefix: String) -> ReactiveMap {
  ReactiveMap(
    layers: dict.new(),
    public_prefix: prefix,
    revision_: 0,
    next_layer_order: 0,
    next_subscription: 1,
    subscribers: [],
  )
}

pub fn revision(map: ReactiveMap) -> Int {
  map.revision_
}

pub fn public_prefix(map: ReactiveMap) -> String {
  map.public_prefix
}

pub fn get_val(map: ReactiveMap, key: String) -> Option(String) {
  case get_entry(map, key) {
    Some(entry) -> Some(entry.value)
    None -> None
  }
}

pub fn get_entry(map: ReactiveMap, key: String) -> Option(ResolvedEntry) {
  resolve(map, key)
}

pub fn get_all_entries(map: ReactiveMap) -> Dict(String, ResolvedEntry) {
  snapshot(map)
}

pub fn get_public_entries(map: ReactiveMap) -> Dict(String, ResolvedEntry) {
  filter_entries(map, True)
}

pub fn get_private_entries(map: ReactiveMap) -> Dict(String, ResolvedEntry) {
  filter_entries(map, False)
}

pub fn set_val(
  map: ReactiveMap,
  key: String,
  value: String,
  public: Option(Bool),
) -> ReactiveMap {
  let #(order, next_order) = case dict.get(map.layers, runtime_layer) {
    Ok(layer) -> #(layer.order, map.next_layer_order)
    Error(_) -> #(map.next_layer_order, map.next_layer_order + 1)
  }

  let layer = case dict.get(map.layers, runtime_layer) {
    Ok(existing) -> Layer(
      ..existing,
      source: "runtime",
      priority: runtime_priority,
      entries: dict.insert(
        existing.entries,
        key,
        RawEntry(value: value, public_override: public),
      ),
    )
    Error(_) -> Layer(
      name: runtime_layer,
      source: "runtime",
      priority: runtime_priority,
      order: order,
      entries: dict.from_list([
        #(key, RawEntry(value: value, public_override: public)),
      ]),
    )
  }

  let after = ReactiveMap(
    ..map,
    layers: dict.insert(map.layers, runtime_layer, layer),
    next_layer_order: next_order,
  )
  commit(map, after)
}

pub fn set_val_in_layer(
  map: ReactiveMap,
  layer_name: String,
  key: String,
  value: String,
  public: Option(Bool),
) -> Result(ReactiveMap, String) {
  case dict.get(map.layers, layer_name) {
    Error(_) -> Error("unknown layer: " <> layer_name)
    Ok(layer) -> {
      let layer = Layer(
        ..layer,
        entries: dict.insert(
          layer.entries,
          key,
          RawEntry(value: value, public_override: public),
        ),
      )
      let after = ReactiveMap(
        ..map,
        layers: dict.insert(map.layers, layer_name, layer),
      )
      Ok(commit(map, after))
    }
  }
}

pub fn replace_layer(
  map: ReactiveMap,
  name: String,
  source: String,
  priority: Int,
  values: Dict(String, EntryInput),
) -> ReactiveMap {
  let #(order, next_order) = case dict.get(map.layers, name) {
    Ok(layer) -> #(layer.order, map.next_layer_order)
    Error(_) -> #(map.next_layer_order, map.next_layer_order + 1)
  }
  let layer = Layer(
    name: name,
    source: source,
    priority: priority,
    order: order,
    entries: raw_entries(values),
  )
  let after = ReactiveMap(
    ..map,
    layers: dict.insert(map.layers, name, layer),
    next_layer_order: next_order,
  )
  commit(map, after)
}

pub fn replace_string_layer(
  map: ReactiveMap,
  name: String,
  source: String,
  priority: Int,
  values: Dict(String, String),
) -> ReactiveMap {
  replace_layer(map, name, source, priority, string_inputs(values))
}

pub fn patch_layer(
  map: ReactiveMap,
  name: String,
  source: String,
  priority: Int,
  values: Dict(String, EntryInput),
) -> ReactiveMap {
  let #(base, next_order) = case dict.get(map.layers, name) {
    Ok(layer) -> #(layer, map.next_layer_order)
    Error(_) -> #(
      Layer(
        name: name,
        source: source,
        priority: priority,
        order: map.next_layer_order,
        entries: dict.new(),
      ),
      map.next_layer_order + 1,
    )
  }
  let entries =
    values
    |> raw_entries
    |> dict.to_list
    |> list.fold(base.entries, fn(entries, pair) {
      let #(key, entry) = pair
      dict.insert(entries, key, entry)
    })
  let layer = Layer(..base, source: source, priority: priority, entries: entries)
  let after = ReactiveMap(
    ..map,
    layers: dict.insert(map.layers, name, layer),
    next_layer_order: next_order,
  )
  commit(map, after)
}

pub fn patch_string_layer(
  map: ReactiveMap,
  name: String,
  source: String,
  priority: Int,
  values: Dict(String, String),
) -> ReactiveMap {
  patch_layer(map, name, source, priority, string_inputs(values))
}

pub fn remove_from_layer(
  map: ReactiveMap,
  layer_name: String,
  key: String,
) -> ReactiveMap {
  case dict.get(map.layers, layer_name) {
    Error(_) -> map
    Ok(layer) -> {
      let layer = Layer(..layer, entries: dict.delete(layer.entries, key))
      let after = ReactiveMap(
        ..map,
        layers: dict.insert(map.layers, layer_name, layer),
      )
      commit(map, after)
    }
  }
}

pub fn remove_layer(map: ReactiveMap, layer_name: String) -> ReactiveMap {
  let after = ReactiveMap(..map, layers: dict.delete(map.layers, layer_name))
  commit(map, after)
}

pub fn set_layer_priority(
  map: ReactiveMap,
  layer_name: String,
  priority: Int,
) -> Result(ReactiveMap, String) {
  case dict.get(map.layers, layer_name) {
    Error(_) -> Error("unknown layer: " <> layer_name)
    Ok(layer) -> {
      let layer = Layer(..layer, priority: priority)
      let after = ReactiveMap(
        ..map,
        layers: dict.insert(map.layers, layer_name, layer),
      )
      Ok(commit(map, after))
    }
  }
}

pub fn set_public_prefix(map: ReactiveMap, prefix: String) -> ReactiveMap {
  let after = ReactiveMap(..map, public_prefix: prefix)
  commit(map, after)
}

pub fn get_layer_order(map: ReactiveMap) -> List(LayerInfo) {
  map.layers
  |> dict.values
  |> list.map(fn(layer) {
    LayerInfo(
      name: layer.name,
      source: layer.source,
      priority: layer.priority,
      order: layer.order,
      size: dict.size(layer.entries),
    )
  })
  |> list.sort(by: compare_layers)
}

pub fn subscribe(
  map: ReactiveMap,
  subscriber: fn(ChangeEvent) -> Nil,
) -> #(ReactiveMap, Int) {
  let id = map.next_subscription
  #(
    ReactiveMap(
      ..map,
      next_subscription: id + 1,
      subscribers: [#(id, subscriber), ..map.subscribers],
    ),
    id,
  )
}

pub fn unsubscribe(map: ReactiveMap, id: Int) -> ReactiveMap {
  ReactiveMap(
    ..map,
    subscribers: list.filter(map.subscribers, fn(pair) {
      let #(candidate, _) = pair
      candidate != id
    }),
  )
}

fn compare_layers(a: LayerInfo, b: LayerInfo) -> order.Order {
  case int.compare(a.priority, b.priority) {
    order.Eq -> int.compare(a.order, b.order)
    other -> other
  }
}

fn raw_entries(values: Dict(String, EntryInput)) -> Dict(String, RawEntry) {
  values
  |> dict.to_list
  |> list.fold(dict.new(), fn(entries, pair) {
    let #(key, EntryInput(value, public)) = pair
    dict.insert(entries, key, RawEntry(value: value, public_override: public))
  })
}

fn string_inputs(values: Dict(String, String)) -> Dict(String, EntryInput) {
  values
  |> dict.to_list
  |> list.fold(dict.new(), fn(entries, pair) {
    let #(key, value) = pair
    dict.insert(entries, key, EntryInput(value: value, public: None))
  })
}

fn resolve(map: ReactiveMap, key: String) -> Option(ResolvedEntry) {
  let winner =
    map.layers
    |> dict.values
    |> list.fold(None, fn(winner, layer) {
      case dict.get(layer.entries, key) {
        Error(_) -> winner
        Ok(raw) ->
          case winner {
            None -> Some(#(layer, raw))
            Some(#(current, _)) -> {
              let replaces =
                layer.priority > current.priority
                || {
                  layer.priority == current.priority
                  && layer.order > current.order
                }
              case replaces {
                True -> Some(#(layer, raw))
                False -> winner
              }
            }
          }
      }
    })

  case winner {
    None -> None
    Some(#(layer, RawEntry(value, public_override))) -> {
      let is_public = case public_override {
        Some(explicit) -> explicit
        None -> string.starts_with(key, map.public_prefix)
      }
      Some(ResolvedEntry(
        value: value,
        source: layer.source,
        is_public: is_public,
        layer: layer.name,
      ))
    }
  }
}

fn snapshot(map: ReactiveMap) -> Dict(String, ResolvedEntry) {
  let keys =
    map.layers
    |> dict.values
    |> list.flat_map(fn(layer) { dict.keys(layer.entries) })
    |> list.unique

  list.fold(keys, dict.new(), fn(entries, key) {
    case resolve(map, key) {
      None -> entries
      Some(entry) -> dict.insert(entries, key, entry)
    }
  })
}

fn filter_entries(map: ReactiveMap, public: Bool) -> Dict(String, ResolvedEntry) {
  map
  |> snapshot
  |> dict.to_list
  |> list.fold(dict.new(), fn(entries, pair) {
    let #(key, entry) = pair
    case entry.is_public == public {
      True -> dict.insert(entries, key, entry)
      False -> entries
    }
  })
}

fn result_option(result: Result(a, Nil)) -> Option(a) {
  case result {
    Ok(value) -> Some(value)
    Error(_) -> None
  }
}

fn commit(before: ReactiveMap, after: ReactiveMap) -> ReactiveMap {
  let before_snapshot = snapshot(before)
  let after_snapshot = snapshot(after)
  let changed =
    list.append(dict.keys(before_snapshot), dict.keys(after_snapshot))
    |> list.unique
    |> list.filter(fn(key) {
      dict.get(before_snapshot, key) != dict.get(after_snapshot, key)
    })
    |> list.sort(by: string.compare)

  case changed {
    [] -> ReactiveMap(..after, revision_: before.revision_)
    _ -> {
      let revision = before.revision_ + 1
      let next = ReactiveMap(..after, revision_: revision)
      list.each(changed, fn(key) {
        let event = ChangeEvent(
          key: key,
          old_entry: result_option(dict.get(before_snapshot, key)),
          new_entry: result_option(dict.get(after_snapshot, key)),
          revision: revision,
        )
        list.each(before.subscribers, fn(pair) {
          let #(_, subscriber) = pair
          subscriber(event)
        })
      })
      next
    }
  }
}
