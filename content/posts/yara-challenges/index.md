---
title: "The Challenges of YARA"
date: 2023-07-11T12:08:09-05:00
draft: false
tags: ['python']
---

Open source security is something fairly important to me. Ensuring individuals have the ability to learn and develop their skills in a secure environment is something I believe everyone has an entitled right to. Unfortunately, the overwhelmingly vast majority of new users are overwhelmed by the options they might find on open source sharing sites and package indexes such as GitHub and the Python Package Index (PyPI).

This overwhelmed feeling can lead to an increased vulnerability for new users to attacks such as typosquatting and dependency confusion. The unfortunate reality is that this presents a barrier to entry that many people may not necessarily even know exists-- that is, identifying and selecting quality dependencies is an acquired skill.

## Identifying Behaviors

When we talk about 'detection' in a cybersecurity context, the average user is going to look at their endpoint detection systems and antiviruses and rely on the level of trust in those systems to secure their particular work environments. Unfortunately, there's a level of implicit trust in certain embedded Python processes that makes detecting these actions virtually impossible. The average flux of the internet makes mapping out specific threats from benign packages exceedingly difficult.

Consider the following:

```python
import subprocess
def not_mal_func(package_name):
 subprocess.run(['pip','install', package_name])
```

This represents a fairly frequent use case for installing dependencies that might be missing for authors that are unaware of the pragmatics of the packaging solutions that exist in Python. Where we would normally identify dependencies in `requirements.txt` or `pyproject.toml`, users will often simply try to import a package, catch the exception, and pip install the missing package.

While this might solve this missing dependency issue entirely, the freedom of choice creates a circumstance where this code snippet is virtually indistinguishable from a malicious codebase. Applying rigorous standards for packaging types, while ideal, does not prevent individuals from doing this within their codebase as well. Ultimately, the freedom of the language limits our ability to detect certain threat profiles as well.

This is but one example of how ambiguity in the language itself can lead to a lack of introspection into the functions themselves. So, how can we possibly profile this? We have a few different ways to detect malicious behavior in Cybersecurity, chiefly signature detection, heuristics analysis, and statistical/analytical modeling (AI/ML).

## Signature Detection

In signature detection, many organizations will use file hashes or YARA rules to map out specific threat profiles. The tradeoff of YARA and file hashing is specificity. Whitespace issues in files will create circumstances where the hash is no longer relevant, and YARA rules in most circumstances cannot distinguish the context that a function is called in.

For example...

```python
import os
def foo():
 os.system('rm -rf /')
```

This clearly presents at minimum an undesirable function to run on a Unix based system. Perhaps we would consider writing a YARA rule to detect it. ..

```python
rule delete_filesystem{
 meta:
  description = "Detects the deletion of the root directory."
  os = "linux"
 strings:
  $command = "rm -rf /"
 condition:
  any of them
}
```

On the above, we're explicitly looking for the string `rm -rf /`. Now let's consider running that on the ~500,000 Python packages on the index right now. What we'll quickly find is that we have numerous flags on non-malicious usage of the string, chiefly in docstrings.

```python
def safe_func():
""" ... prevents system commands such as rm -rf / ... """
 pass
```

We might consider narrowing the scope, to strings such as `os.system('rm -rf /')` but this too, would suffer from issues whereby this can also be invoked as such `subprocess.run(['rm', '-rf', '/'])` and once again, our detection would fail. It shouldn't be difficult to extrapolate that we would be chasing our tails trying to catch every instance of invocation of this precise string, and the functions that could be used to invoke it.

This is but one example of the challenges of writing YARA rules and using signature detection against an entire language's packaging index. In subsequent posts, I intend to discuss SAST tools like Semgrep to attempt to refine the heuristics detection portion of our detection types, and allow YARA to do the bulk majority of the finegrained signature detection instead.
