#!/usr/bin/env bash
set -euo pipefail
caller_dir="$PWD"
project_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
cd "$project_dir"
sha256sum -c dependencies.sha256 >/dev/null
mkdir -p build
# Serialize cache inspection/rebuild across CLI processes; not crypto operations.
command -v flock >/dev/null || { printf 'ERROR flock is required for safe CLI builds\n' >&2; exit 1; }
exec 9>build/.cli-build.lock
flock -x 9
build_digest="$(sha256sum ./*.java dependencies.sha256 | sha256sum | cut -d ' ' -f 1)"
rebuild=false
for source_file in ./*.java; do
  class_name="${source_file##*/}"
  class_name="${class_name%.java}"
  [[ -f "build/$class_name.class" ]] || rebuild=true
done
cache_stamp=()
if [[ -f build/.cli-source-sha ]]; then mapfile -t cache_stamp < build/.cli-source-sha; fi
if [[ "${cache_stamp[0]-}" != "$build_digest" ]]; then rebuild=true; fi
if [[ ! -s build/.cli-classes ]]; then
  rebuild=true
else
  class_manifest_digest="$(sha256sum build/.cli-classes)"
  if [[ "${cache_stamp[1]-}" != "$class_manifest_digest" ]]; then rebuild=true; fi
  # Validate class bytes as well as names; old name-only lists fail and rebuild.
  if ! sha256sum -c --status build/.cli-classes >/dev/null 2>&1; then rebuild=true; fi
fi
if [[ "$rebuild" == true ]]; then
  # A killed/failed compiler must never leave a valid old success marker.
  rm -f build/.cli-source-sha build/.cli-classes build/*.class
  java -m jdk.compiler/com.sun.tools.javac.Main --release 17 -Xlint:all -Werror -cp lib/bcprov-jdk18on-1.86.jar -d build ./*.java
  sha256sum build/*.class > build/.cli-classes
  class_manifest_digest="$(sha256sum build/.cli-classes)"
  printf '%s\n' "$build_digest" "$class_manifest_digest" > build/.cli-source-sha
fi
flock -u 9
exec 9>&-
cd "$caller_dir"
exec java -Xmx512m -cp "$project_dir/build:$project_dir/lib/bcprov-jdk18on-1.86.jar" CryptoCli "$@"
