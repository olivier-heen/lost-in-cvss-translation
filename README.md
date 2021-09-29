# Lost in CVSS translation
**```./cvss-v2-to-v3.sh 'CVSSv3 for CVE-2010-0840: AV:N/AC:L/Au:N/C:P/I:P/A:P/7.5'```**
**```CVSSv3 for CVE-2010-0840: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8```**

CVSSv2 to CVSSv3 translation is a difficult task.
In the example above, no CVSSv3 is known for CVE-2010-0840.
How to automatically propose a decent solution, that an expert may later review?
While plain learning based solution start to appear, I propose another approach only based on vectors.
With this approach a CVSSv2 vector is translated in the CVSSv3 that:
i) Is the most frequently associated in the NVD databases, and 
ii) Keeps the grade difference below a given threshold (such as 3.5).
If no such vector exists the translation fails.

# Tools
- ``lost-in-cvss-translation.sh`` Generate the translators from NVD data.
- ``cvss-v2-to-v3.sh`` CVSSv2 to CVSSv3 translator, more info with --help.
- ``cvss-v3-to-v2.sh`` Backward translator.

# Examples
- ```./cvss-v2-to-v3.sh AV:L/AC:H/Au:N/C:C/I:C/A:C/6.2```          Input from line.
- ```./cvss-v2-to-v3.sh test/test-cvss-v2-to-v3-data.txt```        Input from file.
- ```echo "AV:L/AC:H/Au:N/C:C/I:C/A:C/6.2" | ./cvss-v2-to-v3.sh``` Input from pipe.
- ```./cvss-v3-to-v2.sh AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/7.8``` Backward translation.

# Disclaimer
The translators only provide a consultative advice,
they are not meant for automated / autonomous use.
Some vectors will not be translated, back and forth
e.g., the vectors that do not exist in any NVD data.
The translation relation may not be an involution.
No difference is made among CVSSv3.0 and CVSSv3.1.

# Prerequisites
- ``lost-in-cvss-translation.sh`` needs bash, wget, jq and python.
- ``cvss-v2-to-v3.sh`` and ``cvss-v3-to-v2.sh`` are regular sh scripts.

# TODO
Discard the associations where the grade is too different before computing the most frequent associations.
When several candidate associations exist, peek one according to a heuristic: either minimize the grade difference or minimize the vector "distance".

