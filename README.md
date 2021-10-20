# Lost in CVSS translation

```console
$ ./cvss-conv.sh 'CVE-2010-0840: AV:N/AC:L/Au:N/C:P/I:P/A:P/7.5'
CVE-2010-0840: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8
```

CVSSv2 to CVSSv3 translation is a difficult task.
In the example above, no CVSSv3 is known for CVE-2010-0840.
How to automatically propose a decent solution, that an expert may later review?
While plain learning based solution start to appear, I propose another approach only based on vectors.
With this approach, a CVSSv2 vector is translated in the CVSSv3 that:
i) Is the most frequently associated in the NVD databases, and 
ii) Keeps the score difference below a given threshold (such as 3.5).
If no such vector exists the translation fails.

# Tools
- ``lost-in-cvss-translation.sh`` Generate the translator from NVD data.
- ``cvss-conv.sh`` Match CVSS vectors and translate v2 to v3 and converse.

# Examples
- ```./cvss-conv.sh AV:L/AC:H/Au:N/C:C/I:C/A:C/6.2```          Input from line.
- ```./cvss-conv.sh test/test-conv-data.txt```                 Input from file.
- ```echo "AV:L/AC:H/Au:N/C:C/I:C/A:C/6.2" | ./cvss-conv.sh``` Input from pipe.

# Disclaimer
The translators only provide a consultative advice,
they are not meant for automated / autonomous use.
Some vectors will not be translated, back and forth
e.g., the vectors that do not exist in any NVD data.
The translation relation may not be an involution.
No difference is made among CVSSv3.0 and CVSSv3.1.

# Prerequisites
- ``lost-in-cvss-translation.sh`` needs bash, wget and jq.
- ``cvss-conv.sh`` is a regular sh script.

# TODO
Discard the associations where the score is too different before computing the most frequent associations.
When several candidate associations exist, peek one according to a heuristic: either minimize the score difference or minimize the vector "distance".

