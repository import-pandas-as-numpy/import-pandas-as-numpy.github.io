---
title: "Pico CTF 24 - weirdSnake"
date: 2024-03-26T16:00:00-05:00
draft: false
tags: ['ctf','pico','reverse engineering']
summary: "Reverse engineering disassembled Python bytecode back to the original code."
---

## Introduction

weirdSnake was a challenge in PicoCTF 2024 in the reverse engineering category.
The broad vector is that given a the disassembled output of Python code, you must reverse the code back to the original to derive the flag.

As such, the file we're given is a (fairly large) [Python disassembly](https://docs.python.org/3.11/library/dis.html) text document.

## Solving

There's no particularly strong way to solve this programmatically aside from having a reasonable understanding of the Python interpreter and how Python code looks when disassembled. And so, we'll find ourselves delving into the source code by fragments to try and replicate their behaviors.

For brevity and to save some horizontal space, the first 42 lines involve creating a simple list.

```python
  1           0 LOAD_CONST               0 (4)
    ...
             78 LOAD_CONST              30 (78)
             80 BUILD_LIST              40
             82 STORE_NAME               0 (input_list)
```

This gives us the following list:

```python
input_list = [4, 54, 41, 0, 112, 32, 25, 49, 33, 3, 0, 0, 57, 32, 108, 23, 48, 4, 9, 70, 7, 110, 36, 8, 108, 7, 49, 10, 4, 86, 43, 108, 112, 14, 2, 71, 62, 115, 88, 78]
```

Proceeding through the program we'll go ahead and dump the following bit of stringbuilding here and discuss it, as this is where I hit my first hiccup.

```python
  2          84 LOAD_CONST              31 ('J')
             86 STORE_NAME               1 (key_str)

  3          88 LOAD_CONST              32 ('_')
             90 LOAD_NAME                1 (key_str)
             92 BINARY_ADD
             94 STORE_NAME               1 (key_str)

  4          96 LOAD_NAME                1 (key_str)
             98 LOAD_CONST              33 ('o')
            100 BINARY_ADD
            102 STORE_NAME               1 (key_str)

  5         104 LOAD_NAME                1 (key_str)
            106 LOAD_CONST              34 ('3')
            108 BINARY_ADD
            110 STORE_NAME               1 (key_str)

  6         112 LOAD_CONST              35 ('t')
            114 LOAD_NAME                1 (key_str)
            116 BINARY_ADD
            118 STORE_NAME               1 (key_str)
```

An important thing to observe here is the order of operations, as this will end up being our XOR key, and the string is not as simple as adding up the characters in order.
One would expect that to look something like `J_o3t`, but the order of operations is a bit different than it initially appears.

```python
key_str = "J"
key_str = "_" + key_str # Note the order these are loaded in. We are now at "_J"
key_str = key_str + "o" # _Jo
key_str = key_str + "3" # _Jo3
key_str = "t" + key_str # Again, order of operations. t_Jo3
```

In Python disassembled output, we'll see that list comprehensions are referenced as code objects. These might seem like blackbox functions, but they're actually just appended to the end of the document.  So we have a list comprehension reference:

```python
  9         120 LOAD_CONST              36 (<code object <listcomp> at 0x7f5ef6665d40, file "snake.py", line 9>)
            122 LOAD_CONST              37 ('<listcomp>')
            124 MAKE_FUNCTION            0
            126 LOAD_NAME                1 (key_str)
            128 GET_ITER
            130 CALL_FUNCTION            1
            132 STORE_NAME               2 (key_list)
```

And I chose to replace `LOAD_CONST <listcomp>` with our actual list comprehension object.

```python
Disassembly of <code object <listcomp> at 0x7f5ef6665d40, file "snake.py", line 9>:
  9           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
        >>    4 FOR_ITER                12 (to 18)
              6 STORE_FAST               1 (char)
              8 LOAD_GLOBAL              0 (ord)
             10 LOAD_FAST                1 (char)
             12 CALL_FUNCTION            1
             14 LIST_APPEND              2
             16 JUMP_ABSOLUTE            4
        >>   18 RETURN_VALUE
```

So the real question here is what are we actually doing. In Python, list comprehensions tend to look a bit like...

```python
item for item in iterable
```

And we can see that we have a string, we're loading the global `ord`, which will convert our characters to their ordinal representation (simply the decimal value). So let's try to write out what that might look like...

```python
key_list = [ord(char) for char in key_str]
```

At any point in this we can actually just check our assumptions by disassembling our expected content.

```python
import dis
code = """key_list = [ord(char) for char in key_str]"""
dis.dis(code)
```

To avoid taking up more horizontal content, this does indeed directly match our intended solution, with some slight variations depending on the version of the Python interpreter you're using. But that's where we can cross-check our assumptions as we carry forward and piece together more of the code.

For those that are familiar with CTF style challenges, this should start to look familiar. It appears we're building out an XOR key for our initial list.

At this point ,the challenge is actually solvable, XOR'ing those items with the repeating key will result in the intended solution. But we'll continue to reverse this for posterity.
We have a very long code block next that reverses to a very concise piece of code. Again, having some intuition for what our end-goal is makes this trivial.

```python
5            26 LOAD_NAME                3 (len)
             28 LOAD_NAME                2 (key_list)
             30 CALL_FUNCTION            1
             32 LOAD_NAME                3 (len)
             34 LOAD_NAME                0 (input_list)
             36 CALL_FUNCTION            1
             38 COMPARE_OP               0 (<)
             40 POP_JUMP_IF_FALSE       34 (to 68)

  6     >>   42 LOAD_NAME                2 (key_list)
             44 LOAD_METHOD              4 (extend)
             46 LOAD_NAME                2 (key_list)
             48 CALL_METHOD              1
             50 POP_TOP

  5          52 LOAD_NAME                3 (len)
             54 LOAD_NAME                2 (key_list)
             56 CALL_FUNCTION            1
             58 LOAD_NAME                3 (len)
             60 LOAD_NAME                0 (input_list)
             62 CALL_FUNCTION            1
             64 COMPARE_OP               0 (<)
             66 POP_JUMP_IF_TRUE        21 (to 42)
```

Here we take the length of `key_list` and the length of `input_list` and perform a comparison. If `key_list` is less than (`<`) we're going to extend `key_list` by `key_list`, and repeat until that condition is no longer true. In Python, that looks a bit like this...

```python
while len(key_list) < len(input_list):
    key_list.extend(key_list)
```

The states of our list look something like the below, but keep in mind that we're dealing with ordinals. (So instead of t_Jo3 we're actually dealing with 116, 945, 74, 111, 51).

```plaintext
t_Jo3
t_Jo3t_Jo3
t_Jo3t_Jo3t_Jo3t_Jo3
t_Jo3t_Jo3t_Jo3t_Jo3t_Jo3t_Jo3t_Jo3t_Jo3
```

All we're doing here is padding out `key_list` to be equal in length to `input_list` for the XOR operation. At the end of this operation, both are now at a length of 40. This also results in the comparison operation we mentioned earlier no longer being true, so we exit the `while` loop, and continue.

```python
 15     >>  162 LOAD_CONST              38 (<code object <listcomp> at 0x7f5ef6665df0, file "snake.py", line 15>)
            164 LOAD_CONST              37 ('<listcomp>')
            166 MAKE_FUNCTION            0
            168 LOAD_NAME                5 (zip)
            170 LOAD_NAME                0 (input_list)
            172 LOAD_NAME                2 (key_list)
            174 CALL_FUNCTION            2
            176 GET_ITER
            178 CALL_FUNCTION            1
            180 STORE_NAME               6 (result)
```

Uh oh, another list comprehension. Let's take a peek into that.

```python
Disassembly of <code object <listcomp> at 0x7f5ef6665df0, file "snake.py", line 15>:
 15           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
        >>    4 FOR_ITER                16 (to 22)
              6 UNPACK_SEQUENCE          2
              8 STORE_FAST               1 (a)
             10 STORE_FAST               2 (b)
             12 LOAD_FAST                1 (a)
             14 LOAD_FAST                2 (b)
             16 BINARY_XOR
             18 LIST_APPEND              2
             20 JUMP_ABSOLUTE            4
        >>   22 RETURN_VALUE
```

This is actually super simple here. We can see that the iterable in this scenario is going to be the result of zipping `input_list` and `key_list` together. This operation will create a tuple in the form of `(input_list[n], key_list[n])` or, essentially just pairs for each item for each index.

In the actual list comprehension, we can see that we're going to unpack this sequence into values a and b, and then we're going to perform a binary XOR on these values. Lastly, we'll append these to a list, and then repeat for the rest of the zipped iterables.

In Python, this looks something like this.

```python
result = [a^b for a,b in zip(input_list, key_list)]
```

At this point, we've got the ordinal values for the flag in the proper sequence. So now we can look at the final bit of disassembled Python code.

```python
  8          88 LOAD_CONST               5 ('')
             90 LOAD_METHOD              7 (join)
             92 LOAD_NAME                8 (map)
             94 LOAD_NAME                9 (chr)
             96 LOAD_NAME                6 (result)
             98 CALL_FUNCTION            2
            100 CALL_METHOD              1
            102 STORE_NAME              10 (result_text)

  9         104 LOAD_NAME               11 (print)
            106 LOAD_NAME               10 (result_text)
            108 CALL_FUNCTION            1
            110 POP_TOP
            112 LOAD_CONST               6 (None)
            114 RETURN_VALUE
```

This actually just ends up looking shockingly like what we'd write in Python. `''.join(...)` will join the items of the iterable with the string that it's called on. So since we call it on an empty string, we're essentially just joining the characters.

This presents a problem however, the actual values are still integers, so we'll end up with a strange output. Fear not, that's what the map and char names are for.

We're going to `map` the `chr` function across the result list, and then join each of those items with no string separator. In other words...

```python
result_text = ''.join(map(chr,result))
```

And now we have the fully reversed program. We need to print out this value, so our final Python output is the following:

```python
input_list = [4, 54, 41, 0, 112, 32, 25, 49, 33, 3, 0, 0, 57, 32, 108, 23, 48, 4, 9, 70, 7, 110, 36, 8, 108, 7, 49, 10, 4, 86, 43, 108, 112, 14, 2, 71, 62, 115, 88, 78]
key_str = "J"
key_str = "_" + key_str
key_str = key_str + "o"
key_str = key_str + "3"
key_str = "t" + key_str
key_list = [ord(char) for char in key_str]
while len(key_list) < len(input_list):
    key_list.extend(key_list)
    print(key_list)
result = [a^b for a,b in zip(input_list, key_list)]
result_text = ''.join(map(chr,result))
print(result_text)
```

And if we run this we will receive our flag: `picoCTF{N0t_sO_coNfus1ng_sn@ke_3:a13a97}`

## Summary

What a cool exercise. While not shockingly difficult, I can see this being a bit of a stumbling block for anyone not familiar with Python, specifically with how list comprehensions are structured. I've spent a lot of time doing this, and I definitely got caught up on the `key_str` string building portion by not checking the order of operations.

Disassembled Python bytecode is super cool, but I saw a lot of people asking how they need to disassemble the document passed in the challenge, so I wanted to take a moment to discuss that as well.

The challenge distributes the *already disassembled* bytecode. If we weren't given this, we might want to use something like zrax's [pycdc](https://github.com/zrax/pycdc) to take our Python bytecode from `*.pyc` back to either a representation of the original content (with `pycdc`) or the disassembled output (with `pycdas`). This has a ton of relevant applications, and we do this fairly frequently at Vipyr Security while inspecting packages for malware, especially when heavily obfuscated.

With all of the above in mind, no special tools are needed for this solution, and once some intuition is derived from the underlying code, we can actually simply perform the XOR ourselves without reconstructing the full code output. But it made for a fun exercise.
