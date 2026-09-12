#!/bin/sh
set -eu

usage() {
  echo "usage: scripts/check-peer-authority-paths.sh <typespec-path> <authored-json-schema-path>" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
typespec=$1
schema=$2

[ -f "$typespec" ] || { echo "missing TypeSpec authority: $typespec" >&2; exit 3; }
[ -f "$schema" ] || { echo "missing JSON Schema authority: $schema" >&2; exit 3; }
[ "$typespec" != "$schema" ] || { echo "peer authorities must be distinct files" >&2; exit 4; }

safe_relative_authority() {
  path=$1
  case "$path" in
    /*|../*|*/../*|*/..|..)
      return 1
      ;;
  esac

  old_ifs=$IFS
  IFS='/'
  for component in $path; do
    case "$component" in
      generated|evidence|.canary-evidence|.typespec-json-schema-validator|target|dist|build|artifacts)
        IFS=$old_ifs
        return 1
        ;;
    esac
  done
  IFS=$old_ifs
  return 0
}

safe_relative_authority "$typespec" || {
  echo "TypeSpec authority must be an independently authored repository source, not generated/evidence/build output: $typespec" >&2
  exit 5
}
safe_relative_authority "$schema" || {
  echo "JSON Schema authority must be an independently authored repository source, not generated/evidence/build output: $schema" >&2
  exit 5
}

case "$typespec" in
  *.tsp) ;;
  *) echo "TypeSpec authority must use a .tsp source path: $typespec" >&2; exit 6 ;;
esac
case "$schema" in
  *.json) ;;
  *) echo "JSON Schema authority must use a .json source path: $schema" >&2; exit 6 ;;
esac
