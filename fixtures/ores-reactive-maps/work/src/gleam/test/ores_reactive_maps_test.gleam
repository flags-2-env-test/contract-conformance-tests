import gleam/dict
import gleeunit
import gleeunit/should
import ores_reactive_maps as maps

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn precedence_and_reveal_test() {
  let map =
    maps.new()
    |> maps.replace_string_layer(
      "env",
      "env",
      100,
      dict.from_list([#("PORT", "3000"), #("ORES_PUBLIC_ORIGIN", "https://example.test")]),
    )
    |> maps.replace_string_layer(
      "flags",
      "flags",
      200,
      dict.from_list([#("PORT", "8080")]),
    )

  maps.get_val(map, "PORT") |> should.equal(Some("8080"))
  maps.get_public_entries(map)
  |> dict.get("ORES_PUBLIC_ORIGIN")
  |> should.be_ok

  let before = maps.revision(map)
  let map = maps.patch_string_layer(
    map,
    "env",
    "env",
    100,
    dict.from_list([#("PORT", "3001")]),
  )
  maps.revision(map) |> should.equal(before)

  let map = maps.remove_from_layer(map, "flags", "PORT")
  maps.get_val(map, "PORT") |> should.equal(Some("3001"))
  maps.revision(map) |> should.equal(before + 1)
}

pub fn runtime_and_visibility_test() {
  let map =
    maps.new()
    |> maps.replace_string_layer(
      "env",
      "env",
      100,
      dict.from_list([#("CLIENT_KEY", "x")]),
    )
    |> maps.set_public_prefix("CLIENT_")
    |> maps.set_val("CLIENT_KEY", "runtime", Some(False))

  let assert Some(entry) = maps.get_entry(map, "CLIENT_KEY")
  entry.value |> should.equal("runtime")
  entry.source |> should.equal("runtime")
  entry.layer |> should.equal(maps.runtime_layer)
  entry.is_public |> should.be_false
}
