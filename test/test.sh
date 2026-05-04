#!/bin/bash
# Test build + check, with cache for re-run
# ./test/test.sh

# -- build --

source ./build-cve-db.sh

mkdir -p build ; cd $_

build-cve-db
run-tests

python3 ../build-cve-files-db.py
python3 ../build-dyads-db.py

cd ..
export CVEKERNELTREE=

# -- check --

mkdir -p check ; cd $_

(cd ../build ; cp --parents vulns/tools/target/release/strak ../check )
(cd ../build ; cp --parents vulns/tools/verhaal/verhaal.db ../check )
(cd ../build ; cp --parents cve-files.db ../check )
(cd ../build ; cp --parents dyads.db ../check )

python3 ../restore-dyads.py dyads.db vulns/cve/published

get_file () {
	cp "../$1" .
}

get_file get-cve-list.sh
get_file filter-cve-list.py

chmod +x vulns/tools/target/release/strak

cve_all=$(mktemp)
cve_filtered=$(mktemp)
source ./get-cve-list.sh

get-cve-list "v6.19.3" "$cve_all"
python3 filter-cve-list.py "../test/compile_commands.json" "$cve_all" "$cve_filtered"

echo "Total CVEs: $(jq length "$cve_all")"
echo "CVEs in compile_commands.json: $(jq length "$cve_filtered")"
jq -r '.[]' "$cve_filtered"

rm "$cve_all" "$cve_filtered"
