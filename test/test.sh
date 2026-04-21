#!/bin/bash
# Test build + check, with cache for re-run
# ./test/test.sh

# -- build --

source ./build-cve-db.sh

mkdir -p build ; cd $_

build-cve-db

python3 ../build-cve-files-db.py

cd ..
export CVEKERNELTREE=

# -- check --

mkdir -p check ; cd $_

[ -d "./vulns" ] && {
	(cd vulns ; git pull origin master --depth 1)
} || {
	git clone --depth 1 --no-checkout --filter=blob:none \
	    https://git.kernel.org/pub/scm/linux/security/vulns.git \
	    vulns
	(cd vulns ; git sparse-checkout set cve/published ; git checkout)
}

(cd ../build ; cp --parents vulns/tools/target/release/strak ../check )
(cd ../build ; cp --parents vulns/tools/verhaal/verhaal.db ../check )
(cd ../build ; cp --parents cve-files.db ../check )

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
