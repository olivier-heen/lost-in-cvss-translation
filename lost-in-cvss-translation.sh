#!/bin/bash

HELP='
lost-in-cvss-translation.sh <workdir>
This script generates the translation scripts cvss-v2-to-v3.sh and cvss-v3-to-v2.sh.
The main operations are: download NVD data in <workdir> if necessary, extract the relevant fields, compute the most frequent CVSSv2/CVSSv3 associations, remove associations where the grade difference is too high, generate corresponding translation scripts (back and forth).
NOTES: The complete execution can take several minutes. The <workdir> is not deleted automatically so that re-run are faster and so that intermediate files can be reused if needed. Wget, jq and python are needed.
'
VERS='v1.0 2021-09'
COPY='Olivier HEEN'
MAXI='3.5' # Associated CVSSv2/CVSSv3 with grade difference above MAXI will not be used for learning.

# Parse and help
[[ "$#" != "1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]] &&	\
echo "${HELP}" && exit

# Create and enter working directory
WDIR="$1" ; mkdir -p "${WDIR}"
[[ ! -d "${WDIR}" ]] && echo "$0: can not create ${WDIR}." && exit 1
pushd "${WDIR}" >& /dev/null

echo -n "Downloading the data-sets for years 20"
for YEAR in $(seq -w 02 21); do
    FILE="nvdcve-1.1-20${YEAR}.json"
    if [[ ! -f "${FILE}" ]]; then
        wget -q "https://nvd.nist.gov/feeds/json/cve/1.1/${FILE}.zip"
        unzip -o -q "${FILE}.zip" && rm "${FILE}.zip"
        touch last-data-update
    fi
    echo -n "$YEAR "
done
[[ -f last-data-update ]] || touch last-data-update
echo

echo -n "Selecting useful fields (can take minutes)"
if [[ last-data-update -nt cve-cvss.csv ]]; then
    cat nvdcve-1.1-20??.json	|\
    jq -r '.CVE_Items[]|"\(.cve.CVE_data_meta.ID)	\((.impact|"\(.baseMetricV3.cvssV3.vectorString)/\(.baseMetricV3.cvssV3.baseScore)/	/\(.baseMetricV2.cvssV2.vectorString)/\(.baseMetricV2.cvssV2.baseScore)/"))"'	  \
    > cve-cvss.csv
fi
echo

echo -n "Normalizing the grades (x->x.0, 10->A.0)"
sed -i 's/\/\([0-9]\)\//\/\1.0\//g' cve-cvss.csv
sed -i 's/\/10/\/A.0/g' cve-cvss.csv
sed -i '/\(null.*\)\{4\}/d' cve-cvss.csv
echo
#sed -i 's/CVSS:3.[01]//' cve-cvss.csv
#grep -v '\(null.*\)\{4\}'

echo -n "Making a list of all the CVSS v2"
cut -f3 cve-cvss.csv | grep -v null | cut -b2-  > v2.csv
echo

echo -n "Making a list of all the CVSS v3"
cut -f2 cve-cvss.csv | grep -v null | cut -b10- > v3.csv
echo

echo -n "Selecting vulns having v2 and v3"
for VERS in "3.0" "3.1"; do # Ignore the nuance CVSS3.0 vs. CVSS3.1
    cut -f2- cve-cvss.csv	|\
    grep -v null	|\
    grep "^CVSS:${VERS}\/"	|\
    cut -d\/ -f2-	 \
    > "v${VERS}-v2.csv"
done
paste -d\/ <(cut -f2 v3.?-v2.csv | cut -b2-) <(cut -f1 v3.?-v2.csv) > v2-v3.csv
paste -d\/ <(cut -f1 v3.?-v2.csv) <(cut -f2 v3.?-v2.csv | cut -b2-) > v3-v2.csv
echo

echo -n "Learning v2 to v3 pseudo-mapping"
# For each existing V2 vector with known V3 associations
for V2 in $(cut -d\/ -f-6 v2.csv | sort -u); do
    # Compute the most frequent association 
    grep "$V2" v2-v3.csv | sort | uniq -c | sort -gr | head -n1
done	|\
grep -v " [0] "	 \
> learn-v2-to-v3
cat << EOF > cvss-v2-to-v3.sh
#!/bin/sh
# Generated "$(date -u)" with "$0"
[ "\$#" -ne "1" ] || [ "$1" = "--help" ] && echo "Usage: cvss-v2-to-v3.sh <FILE or vector>.\nReplace CVSSv2 vectors by their most frequently associated CVSSv3 vectors" && exit
[ -f "\$1" ] && CMD="cat" || CMD="echo"
\$CMD \$1 | sed --sandbox "
EOF
# Heuristic: do not keep assciations where the grade difference exceeds a threshold (e.g. 3.5)
while read LINE; do
    GRADEv2=$(echo "$LINE" | cut -d\/ -f7 | sed 's/A/10/')
    GRADEv3=$(echo "$LINE" | cut -d\/ -f17 | sed 's/A/10/')
    python -c "if ($GRADEv3-$GRADEv2<=3.5): print('$LINE')"
done < learn-v2-to-v3	|\
sed -E 's,^.* (.*)\/[0-9A]\.[0-9]//(.*).,s \1\\(\/[0-9]\\.[0-9]\\|\/10\\|\/10\\.0\\|\\) \2 ;,' >> cvss-v2-to-v3.sh
cat << EOF >> cvss-v2-to-v3.sh
s AV:./AC:./Au:./C:./I:./A:.\\(\/[0-9]\\.[0-9]\\|\/10\\|\/10\\.0\\|\\) unknown-cvss ;
"
EOF
echo

echo -n "Learning v3 to v2 pseudo-mapping"
for V3 in $(cut -d\/ -f-8 v3.csv | sort -u); do
    grep "$V3" v3-v2.csv | sort | uniq -c | sort -gr | head -n1
done	|\
grep -v " [0] "	 \
> learn-v3-to-v2
cat << EOF > cvss-v3-to-v2.sh
#!/bin/sh
# Generated "$(date -u)" with "$0"
[ "\$#" -ne "1" ] || [ "$1" = "--help" ] && echo "Usage: cvss-v3-to-v2.sh <FILE or vector>.\nReplace CVSSv3 vectors by their most frequently associated CVSSv2 vectors" && exit
[ -f "\$1" ] && CMD="cat" || CMD="echo"
\$CMD \$1 | sed --sandbox "
EOF
while read LINE; do
    GRADEv2=$(echo "$LINE" | cut -d\/ -f9 | sed 's/A/10/')
    GRADEv3=$(echo "$LINE" | cut -d\/ -f17 | sed 's/A/10/')
    python3 -c "if ($GRADEv3-$GRADEv2<3): print('$LINE')"
done < learn-v3-to-v2	|\
#sed -E 's,^.* (.*)//(.*).,s \1 \2 ;,' >> cvss-v3-to-v2.sh
sed -E 's,^.* (.*)\/[0-9A]\.[0-9]//(.*).,s \1\\(\/[0-9]\\.[0-9]\\|\/10\\|\/10\\.0\\|\\\/\\|\\) \2 ;,' >> cvss-v3-to-v2.sh
cat << EOF >> cvss-v3-to-v2.sh
s AV:./AC:./PR:./UI:./S:./C:./I:./A:.\\(\/[0-9]\\.[0-9]\\|\/10\\|\/10\\.0\\|\\) unknown-cvss ;
"
EOF
echo

popd
cp ${WDIR}/cvss-v?-to-v?.sh .
echo -n "Generation complete, results are:"
ls cvss-v?-to-v?.sh
