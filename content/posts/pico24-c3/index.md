---
title: "Pico CTF 24 - C3"
date: 2024-03-26T16:00:00-05:00
draft: false
tags: ['ctf','pico','cryptography']
summary: "Working through security by obscurity with the PicoCTF 2024 C3 challenge."
---

## Introduction

C3 (Custom Cyclical Cipher) was a challenge in the Cryptography category of PicoCTF 2024. Given a plain ciphertext and the code used to produce it, players were given the broad vector of reversing the ciphertext back to plaintext.

As far as hints go, C3 didn't offer much in the way of solving, but mused that "Modern crypto schemes don't depend on the encoder to be secret, but this one does."

## Solving

This is a relatively straightforward solve, but it actually took me a bit to get to the bottom of the solution for reasons we'll discuss in a bit.

### The Ciphertext

```plaintext
DLSeGAGDgBNJDQJDCFSFnRBIDjgHoDFCFtHDgJpiHtGDmMAQFnRBJKkBAsTMrsPSDDnEFCFtIbEDtDCIbFCFtHTJDKerFldbFObFCFtLBFkBAAAPFnRBJGEkerFlcPgKkImHnIlATJDKbTbFOkdNnsgbnJRMFnRBNAFkBAAAbrcbTKAkOgFpOgFpOpkBAAAAAAAiClFGIPFnRBaKliCgClFGtIBAAAAAAAOgGEkImHnIl
```

We're given the above ciphertext. There's nothing incredibly alarming here. We can see that there's no digits present in the ciphertext itself, nor any nonprintable characters, so of the assumptions we can draw thus far, we can fairly confidently say that this is going to use a pretty limited character set.

When approaching ciphertexts, it's always a good idea to keep in mind the character frequency. In this case, we have several characters that appear more frequently than others. A (26), F(24) followed by D(14), B(12) and so on down the list.

This doesn't end up being particularly relevant to this challenge, but a good habit to make is to start looking early for obvious patterns that might match up to the English language. For instance, E is the most common letter in the English language, and as such, we might assume that A decodes to E. I can save you some effort and confirm that it does not.

### The Cipher

```python
chars = "abcdefghijklmnopqrstuvwxyz"

lookup1 = "\n \"#()*+/1:=[]abcdefghijklmnopqrstuvwxyz"
lookup2 = "ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst"

out = ""

prev = 0
for char in chars:
  cur = lookup1.index(char)
  out += lookup2[(cur - prev) % 40]
  prev = cur

sys.stdout.write(out)
```

I've adjusted the above for Python 3. So we can see we have, as the challenge suggested, a cyclical cipher that will do the following.

1. We will look for the character in lookup 1.
2. We will take the index of that character, subtract the previous index, and then use modulo `%` to 'wrap' it within the array. (The array's length is 40.)
3. We will then store the current character's index as previous, and repeat.

### The Solve

Since variable previous is equal to zero on the first iteration, we have all the information we need to work back through the ciphertext and derive the cleartext. I wrote a simple Python script to do this.

```python
lookup1 = "\n \"#()*+/1:=[]abcdefghijklmnopqrstuvwxyz"
lookup2 = "ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst"

with open('ciphertext','r') as f:
    ciphertext = f.read()


prev = 0
out=""
for letter in ciphertext:
    ind = lookup2.index(letter)
    for x in range(100000):
        if (x - prev) % 40 == ind:
            out += lookup1[x]
            prev = x
            break
print(out)
```

We create both lookup tables again, and read the file for convenience sake.
And then we get to solving...

1. We reference the letter of the ciphertext, and obtain its index.
2. We then loop over an unnecessarily large range, which easily could've been much smaller but for the sake of simplicity, was arbitrarily chosen to be high. This is because we want to afford previous the ability to be larger than current, in order for it to 'wrap' with the modulo operator.
3. When we find a value minus the previous value, modulus 40 equal to the index of the current letter, we can confirm that that is our previous index.
4. We can now add that to our output string, and then set our previous equal to the `x` that we just found.

We now simply need to run this script on the ciphertext and we obtain our cleartext:

```python
#asciiorder
#fortychars
#selfinput
#pythontwo

chars = ""
from fileinput import input
for line in input():
    chars += line
b = 1 / 1

for i in range(len(chars)):
    if i == b * b * b:
        print chars[i] #prints
        b += 1 / 1
```

Now, I got stuck here for quite awhile. I took the steps to convert this to Python 3 from Python 2 before carrying on...

```python
with open('original.py') as f:
    ciphertext = f.read()
asciichars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
b = 1
for i in range(len(ciphertext)):
    if i == b*b*b:
        print(ciphertext[i])
        b += 1
```

`#selfinput` is the big hint here, and ultimately what got us to the end of the challenge. I fed the cleartext that we reversed from step 1 into the remade Python3 script, and I was able to obtain the flag. `picoCTF{adlibs}`

For clarity, this steps over each character in the original script, and if its index is equal to 1^3, 2^3, 3^3, ... it will add the character to the output string.

## Summary

Relying on the obfuscation of a cipher does not always guarantee any level of security of the ciphertext, and with a bit of Python knowhow, we found that we were able to rapidly derive the plaintext and flag for this specific challenge.
