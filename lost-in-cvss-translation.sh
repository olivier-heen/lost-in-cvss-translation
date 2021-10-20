#!/bin/bash

HELP='
lost-in-cvss-translation-2.sh [ -h | --help ]
Generate CVSS translation script cvss-conv.sh
The generation can take several minutes.
Temporary files in /tmp are not erased.
wget, jq and python are needed.
'
VERS='v2.0 2021-10'
COPY='Olivier HEEN'
MAXI='3.5' # Maximum tolerated CVSSv2/CVSSv3 grade difference.

# Parse and help
[ "$1" = "-h" ] || [ "$1" = "--help" ] && echo "${HELP}" && exit

# Create and enter working directory (POSIX /tmp is assumed)
pushd "/tmp" >& /dev/null

echo -n "Downloading the data-sets for years 20"
for YEAR in $(seq -w 02 21); do
    FILE="nvdcve-1.1-20${YEAR}.json"
    if [ ! -f "${FILE}" ]; then
        wget -q "https://nvd.nist.gov/feeds/json/cve/1.1/${FILE}.zip"
        unzip -o -q "${FILE}.zip" && rm "${FILE}.zip"
        touch last-data-update
    fi
    echo -n "${YEAR} "
done
[ -f last-data-update ] || touch last-data-update
echo

echo -n "Selecting only the useful fields"
if [ last-data-update -nt cve-cvss.csv ]; then
    cat nvdcve-1.1-20??.json	|\
    jq -r '.CVE_Items[]|"\(.cve.CVE_data_meta.ID)	\((.impact|"\(.baseMetricV3.cvssV3.vectorString)/\(.baseMetricV3.cvssV3.baseScore)/	/\(.baseMetricV2.cvssV2.vectorString)/\(.baseMetricV2.cvssV2.baseScore)/"))"'	  \
    > cve-cvss.csv
fi
echo

echo -n "Normalizing (x->x.0 and 10->A.0)"
sed -i 's/\/\([0-9]\)\//\/\1.0\//g' cve-cvss.csv
sed -i 's/\/10/\/A.0/g' cve-cvss.csv
sed -i '/\(null.*\)\{4\}/d' cve-cvss.csv
echo
#sed -i 's/CVSS:3.[01]//' cve-cvss.csv " Other heuristics attempts

echo -n "Selecting vulns having v2 and v3"
for VERS in "3.0" "3.1"; do # Ignore the nuance CVSS3.0 vs. CVSS3.1
    cut -f2- cve-cvss.csv	|\
    grep -v null	|\
    grep "^CVSS:${VERS}\/"	|\
    cut -d\/ -f2-	>\
   "v${VERS}-v2.csv"
done

paste -d\/ <(cut -f2 v3.?-v2.csv | cut -b2-) <(cut -f1 v3.?-v2.csv)	|\
sed -E 's AV:(.)/AC:(.)/Au:(.)/C:(.)/I:(.)/A:(.)/(...)// \1\2\3\4\5\6\7 '	|\
sed -E 's AV:(.)/AC:(.)/PR:(.)/UI:(.)/S:(.)/C:(.)/I:(.)/A:(.)/(...)/ \1\2\3\4\5\6\7\8\9 '	>\
v2-v3.csv

paste -d\/ <(cut -f1 v3.?-v2.csv) <(cut -f2 v3.?-v2.csv | cut -b2-)	|\
sed -E 's AV:(.)/AC:(.)/PR:(.)/UI:(.)/S:(.)/C:(.)/I:(.)/A:(.)/(...)// \1\2\3\4\5\6\7\8\9 '	|\
sed -E 's AV:(.)/AC:(.)/Au:(.)/C:(.)/I:(.)/A:(.)/(...)/ \1\2\3\4\5\6\7 '	>\
v3-v2.csv
echo

echo -n "Learning v2 to v3 pseudo-mapping"
cat << EOF > cvss-conv.sh
#!/bin/sh
# Generated "$(date -u)" with "$0"
[ "\$1" = "--help" ] && echo "Usage: cvss-conv.sh <FILE or vector>" && exit
[ "\$#" -eq "0" ] && CMD="" || [ -f "\$1" ] && CMD="cat" || CMD="echo"
\${CMD} \$1 | sed --sandbox "
s AV:\(.\)/AC:\(.\)/Au:\(.\)/C:\(.\)/I:\(.\)/A:\(.\)\(/[0-9]\.[0-9]\|/10\|/10\.0\|\/\|\) §\1\2\3\4\5\6§ g;
s AV:\(.\)/AC:\(.\)/PR:\(.\)/UI:\(.\)/S:\(.\)/C:\(.\)/I:\(.\)/A:\(.\)\(/[0-9]\.[0-9]\|/10\|/10\.0\|\/\|\) §\1\2\3\4\5\6\7\8§ g;
" | sed --sandbox "
EOF
for V2 in $(cut -b-6 v2-v3.csv | sort -u); do
    # Compute the most frequent association 
    grep "${V2}" v2-v3.csv | sort | uniq -c | sort -gr | head -n1
done	|\
grep -v " [0] "	|\
while read LINE; do
    GRADEv2=$(echo "${LINE}" | cut -b9-11 | sed 's/A/10/')
    GRADEv3=$(echo "${LINE}" | cut -b20-22 | sed 's/A/10/')
    DIST=$(echo "${GRADEv3}-${GRADEv2}" | bc | tr -d '-')
    [ 1 -eq $(echo "${DIST}<=${MAXI}" | bc) ] && echo "${LINE}"	|\
    sed -E 's/^[^ ]* (......)...(...........)/s §\1§ §\2§ g/'
done	>>\
cvss-conv.sh
cat << EOF >> cvss-conv.sh
" | sed --sandbox "
EOF
echo

echo -n "Learning v3 to v2 pseudo-mapping"
for V3 in $(cut -b-8 v3-v2.csv | sort -u); do
    # Compute the most frequent association 
    grep "${V3}" v3-v2.csv | sort | uniq -c | sort -gr | head -n1
done	|\
grep -v " [0] "	|\
while read LINE; do
    GRADEv2=$(echo "${LINE}" | cut -b9-11 | sed 's/A/10/')
    GRADEv3=$(echo "${LINE}" | cut -b18-20 | sed 's/A/10/')
    DIST=$(echo "${GRADEv3}-${GRADEv2}" | bc | tr -d '-')
    [ 1 -eq $(echo "${DIST}<=${MAXI}" | bc) ] && echo "${LINE}"	|\
    sed -E 's/^[^ ]* (........)...(.........)/s §\1§ §\2§ g/'
done	>>\
cvss-conv.sh
# Adding transforms for unknown vectors and transforms to avoid v2->v3-v2->... loops (assuming § is rare)
cat << EOF >> cvss-conv.sh
" | sed --sandbox "
s §......§ unknown-cvss-v2 g;
s §........§ unknown-cvss-v3 g;
s §\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(...\)§ AV:\1/AC:\2/Au:\3/C:\4/I:\5/A:\6/\7 g;
s §\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(...\)§ AV:\1/AC:\2/PR:\3/UI:\4/S:\5/C:\6/I:\7/A:\8/\9 g;
"
EOF
echo

echo "The translator is available as: "
popd >& /dev/null
mv /tmp/cvss-conv.sh .
ls cvss-conv.sh
