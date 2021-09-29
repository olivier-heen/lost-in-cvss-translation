# Lost in CVSS translation
CVSSv2 to CVSSv3 translation is a difficult task.
While plain learning based methods already exist,
I propose another approach only based on vectors.
A CVSSv2 vector is translated in the CVSSv3 that:
1. Is the most frequently associated in NVD databases.
2. Keeps the grade difference below a given threshold.

If no such vector exists, the translation fails.

# Tools
- ``lost-in-cvss-translation.sh`` Generate the translators from NVD data.
- ``cvss-v2-to-v3.sh`` CVSSv2 to CVSSv3 translator, more info with --help.
- ``cvss-v3-to-v2.sh`` Inverse translator, e.g. for backward comparisons.

# Examples
<TODO>

# Disclaimer
The translators only provide a consultative advice.
They are not meant for automated / autonomous use.
Some vectors will not be translated, back and forth,
(e.g. the vectors that do not exist in any NVD data).
The translation relation may not be an involution.
No difference is made among CVSSv3.0 and CVSSv3.1.

# Prerequisites
``lost-in-cvss-translation.sh`` needs bash, wget, jq and python.
``cvss-v2-to-v3.sh`` and ``cvss-v3-to-v2.sh`` are regular sh scripts.

# TODO
Discard the associations where the grade is too different before computing the most frequent associations.
