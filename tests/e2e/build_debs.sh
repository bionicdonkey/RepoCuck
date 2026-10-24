#!/usr/bin/env bash
# Builds fixture .deb files with dpkg-deb into $1 (default tests/e2e/fixture/assets).
set -euo pipefail
out="${1:-$(dirname "$0")/fixture/assets}"
mkdir -p "$out"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

mk() { # name version arch [extra control lines...]
  local name="$1" ver="$2" arch="$3"; shift 3
  local d="$work/${name}_${ver}_${arch}"
  mkdir -p "$d/DEBIAN" "$d/usr/share/$name"
  {
    echo "Package: $name"; echo "Version: $ver"; echo "Architecture: $arch"
    echo "Maintainer: Fixture <fixture@example.com>"; echo "Section: utils"; echo "Priority: optional"
    echo "Description: Fixture package $name"; echo " Built for RepoCuck end-to-end tests."
    for l in "$@"; do echo "$l"; done
  } > "$d/DEBIAN/control"
  echo "$name $ver $arch" > "$d/usr/share/$name/VERSION"
  mkdir -p "$d/usr/bin"; printf '#!/bin/sh\necho "%s %s %s"\n' "$name" "$ver" "$arch" > "$d/usr/bin/$name"; chmod 755 "$d/usr/bin/$name"
  dpkg-deb --root-owner-group -Zgzip --build "$d" "$out/${name}_${ver//:/_}_${arch}.deb" >/dev/null
}
for v in 1.0.0 1.1.0; do
  for a in amd64 arm64 armhf; do mk fooapp "$v" "$a"; done
done
mk fooapp-data 1.0.0 all
mk baddigest 1.0 amd64
mk libc6 99.0 amd64            # reserved name: must be quarantined
mk epochpkg 1:2.0 amd64        # epoch: must be quarantined
# a second repository ("fork") offering the same identity with different bytes
mkdir -p "$out/fork"
work2="$(mktemp -d)"; trap 'rm -rf "$work" "$work2"' EXIT
d="$work2/fooapp"; mkdir -p "$d/DEBIAN" "$d/usr/bin"
printf 'Package: fooapp\nVersion: 1.0.0\nArchitecture: amd64\nMaintainer: Fork <fork@example.com>\nDescription: Forked fooapp\n' > "$d/DEBIAN/control"
printf '#!/bin/sh\necho forked\n' > "$d/usr/bin/fooapp"; chmod 755 "$d/usr/bin/fooapp"
dpkg-deb --root-owner-group -Zgzip --build "$d" "$out/fork/fooapp_1.0.0_amd64.deb" >/dev/null
echo "# not a deb" > "$out/README.txt"
ls -la "$out"
