---
title: "The XZ Backdoor Dilemma"
date: 2024-03-31T00:00:00-05:00
draft: false
tags: ['open source','security']
---

There's a lot of information floating around right now on the xz backdoor.
I have very few doubts that over the next few weeks/months, we'll be inundated with commentary
regarding how we should've seen this, how open-source software is a security vulnerability in itself,
and that if we simply paid developers more, the solution would magic itself away.

While some of these are true-- notably that open-source software developers largely prop up the backbone of the internet,
I'd feel remiss if I didn't add some level of commentary on the whole issue from the perspective of someone dealing with the actions
and consequences of open source security in general.

## Background

First, to offer an at-a-glance background of what exactly motivated this article. On March 29, 2024, Andres Freund
posted to the OpenWall mailing list that he'd found a vulnerability in the xz software. Specifically, a backdoor.

xz is a common dependency for both sshd and systemd on systems that selectively utilize both of these services, and
has a pretty dramatic attack surface. Distributions like Kali/Arch were "compromised" (though the effects of this compromise are both
are incredibly limited and very niche, to the point where there is an incredibly limited threat to end users despite common Internet sentiment.)

To avoid rehashing the entirity of the article, which you can [read here](https://www.openwall.com/lists/oss-security/2024/03/29/4), the backdoored
xz tarball builds liblzma with a bit of code inserted to manipulate the PLT of `RSA_public_decrypt` to its own function, essentially arbitrarily
replacing that code with its own.

This has a number of *possible* consequences, and while I'll avoid speculating publicly, there's a [fair bit of research](https://bsky.app/profile/filippo.abyssdomain.expert/post/3kowjkx2njy2b)
that is pointing to compelling conclusions that this was a backdoor that enabled Remote Code Execution (RCE) via values stored in an attacker's RSA public key.

There is a lot of information regarding the author as well; however much of it seems to not be grounded in reality-- and I think Internet conspiracy
theorists are having a field day with the current state of this security issue. That said, one thing is for certain, this attack was quite
mature, sophisticated, and well thought out.

## Is Open Source Software a Security Risk?

This is the question on everyone's mind right now. When we think of open source software, minds will generally wander to the idea
that we're just arbitrarily pulling packages off of Github sight unseen. I'm not sure if this is a reality though in most ecosystems.

A lot of this commentary is going to be framed from the perspective of the Python ecosystem, but I think it has some level of translation across
almost every ecosystem anyway. When we look at major package creators (think, Numpy, Pandas, Black, etc.) we're looking at maintainer teams,
not singular maintainers propping up a major project. This, in my mind, is the singular and most compelling failure in the xz fiasco in general.

It kind of baffles me that a singular maintainer was left in charge of this package, and their commits went more or less entirely unchecked.
The wonders of having a team responsible of a large project isn't just that the responsibility is divided; but it is also that you can implement a more robust code
review processes in general.

What does this look like at an organizational level? At Vipyr, the open-source software security organization that I run, we have a review process
that compells individuals via codeowner files to perform security and core developer reviews. These individuals can never be the initial committer,
and except in extremely rare cases, cannot be the same person. (For transparency, organizational administrators reserve the ability to perform code-review
and security reviews simultaneously, but still cannot side-step the requirement for reviews themselves.)

As such, at a bare minimum, **two** individuals touch *every single commit to our repositories*, and in normal operating tempo, that will be *three* individuals.
Now, I'm under no illusion that Vipyr is a critical project, but it seems asinine to me that a group of rag-tag college students were able to directly implement a more robust
review process than a critical project maintainer; even when our commits themselves largely extend past 2000 line diffs.

Does this slow the pace of development down? Absolutely, there's zero questions about that. We would be much faster if we simply disregarded
the review process entirely and allowed commits to our main branch from core developers. And realistically, our tolerance for security risks
is actually fairly high-- we can accept a pretty large quantity of risk by virtue of the way our systems are designed and isolated.
(I might cry over my cheerios for a few days if my tables get dropped, but it's not really going to affect our bottom line.)

Now, it's easy to preach about this from atop a pedestal. Certainly we've never implemented any security vulnerabilites and footgunned ourselves in that regard.
After all, I'm an infosec professional! Just kidding, we had a critical endpoint exposed on our API without authentication for months before a code security
review caught it. But that just underpins the importance of these processes in general; without that review process, nobody would've seen it, and we would've
been in for a world of hurt.

To kind of realign ourselves with the question I posed, what does this actually mean for open source security though? Certainly we don't have the ability
to arbitrarily assign key maintainers, and that may also introduce some concerns itself-- do you trust the person doing the code review? What if that person
is unavailable? Do we mandate critical software now have teams dedicated to them to maintain the code? And chiefly, if we're mandating this, it seems like...
pay them as well.

### Defense-In-Depth isn't just network design

There are a few scenarios where this behavior could've come to be: Was Jia Tan's account compromised? Or even more sinister, were they
social engineering people for years to successfully implement this backdoor?

Somehow, I doubt we're going to get the actual answer to this, but it does bring up an interesting idea. What if they simply didn't have
the ability to do this without raising alarms? We preach all the time in the open-source community about contributing to these communities and projects,
but what does that actually mean? Well, to me-- contributing is any meaningful progress towards the development of that package. And security is, by its very nature,
a requirement of development (in an ideal world). So it's not a farfetched idea that involvement with open source could simply be effectively performing
check-and-balance code reviews for project maintainers as well.

For instance, commits made by Lasse Collin (the original xz maintainer) highlighted this entertaining change to the Landlock sandbox check, which resulted in the
sandbox check actually just simply being disabled.

```diff
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1001,7 +1001,7 @@ if(NOT SANDBOX_FOUND AND ENABLE_SANDBOX MATCHES "^ON$|^landlock$")
         #include <linux/landlock.h>
         #include <sys/syscall.h>
         #include <sys/prctl.h>
-.
+
         void my_sandbox(void)
         {
             (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
```

Can you spot the issue? It's quite subtle, and hard to notice without an acute observation (and maybe some pretext.) The additional character that was removed by Lasse in his
cleanup efforts here actually disabled the sandbox check entirely by causing the code to error.

Now, we can all point the finger at how we should've caught that, and I'm inclined to agree-- **we should have.** Collectively, the open source software community
probably holds some blame for not encouraging (or enforcing, in some cases) the code security review process.

So how can we possibly fix this?

### Getting Involved in Security Reviews

I would generally encourage individuals to get involved not only with the development of software in the open source ecosystems, but the security as well. Tools like
Semgrep can act as excellent ways to amplify your sphere of influence as an application security professional or cybersecurity-inclined software engineer across
a massive amoung of data.

I'll never pretend to be a developer. My ability to produce code is limited at best, and I have all but a loose syntactic recognition of most languages aside from
Java and Python. But what I do know is that I can take a demonstration of a vulnerability, write a [Semgrep](https://semgrep.dev/) rule, and apply that knowledge across virtually
any codebase that I'd be interested in.

Is this going to find binary malware? Nah-- we've got YARA for that (and in this case it wouldn't have done a whole lot), but we it isn't an extreme
leap to look at the current code and go *"Well, wait, we could've prevented some of this."* And that's where I rest my entire argument. We have the tools
to start looking at open source security more critically than we currently do, and to exert professional knowledge across numerous domains.

Vipyr's Dragonfly framework currently processes about 9000 lines of code per second, with the ability to sustain that almost indefinitely.
I don't believe in earnest that the open-source software that most individuals are using are sustaining that level of upstream activity for any sustained
period of time. Consequentially, I know this to be an accomplishable task. While it's difficult, it is certainly *possible*.

As such, if you're a security professional and open source security enthusiast, a wonderful opportunity for you to get involved is to write rules
to detect behaviors such as this; and to embrace wholesale the idea that security contributions to the broader open-source ecosystem can actually
be in the form of aggregate detection instead of raw *Hey your authentication here isn't working!* (Though both aren't bad either!)

## Combinatorial Explosion: A Dependency Issue

One of the common 'stabs' towards this issue I've seen in various discussions on social media is that as a developer, it's your responsibility to review
dependencies prior to accepting them into your codebase. I find this a little reductionist for a couple of reasons.

I've done at least enough development to understand how much of a pain it is to maintain dependencies. About seven months ago, I started
development on the Vipyr Security website. It's a simple Astro site using onWidget's AstroWinds template. Our site itself doesn't have a whole lot in the
way of functionality, and it's largely just the world's most overengineered static site. How many dependencies do you think it takes to generate the
seven or eight pages we have on our website? 10? 100? 500?

At one point, our SBOM (Software Bill of Materials) was over **nine-hundred** npm packages.

I do not care how big your development team is, you cannot possibly secure this yourself. Resultant to that, at some point, you're accepting
some arbitrary code entry into your codebase. So... how do we secure this?

The answer: **You probably can't.** At least, not in the way you're thinking of. It seems reasonable to me to review new introductions into your SBOM
itself; I would like to know when I have a new package added or removed from my dependency list. And I will and brief myself on changes
to this overview of my code composition. But I cannot possibly dictate the level of time it might take to review any changes to these dependencies themselves.

### Enter Software Composition Analyis (SCA)

What a fancy term for something so idiomatic... We spoke briefly about the idea of dedicating teams of maintainers and security reviewers to prevent
a single compromise from tainting the supply chain? What if we could assign these codebases some sort of reputation score, identify projects that might be
vulnerable in this regard, and suggest alternatives? That's where Software Composition Analysis comes in.

If we take aggregate threat information from various feeds such as Github Security Advisories (GHSA), Common Vulnerabilities and Exploits (CVE) and
static application security testing (SAST) solutions like Semgrep, Snyk, etc., and we apply them across our entire SBOM, we kind of arrive at a very
simple SCA system.

If we track the flow of potentially untrusted code entering our source code and the various means in which it's being added, we can start to build out
a threatmap of sourcecode that might be more or less secure, and prioritize our review efforts towards these sources. This makes the dependency issue a bit more digestable.
Instead of reviewing 900 packages, I can now trust that Snyk probably did due dilligence in scanning (or at least, a better job than I'll do) on
a large portion of these packages, and focus myself on packages that have not yet reached maturity that may be introduced into my codebase, or packages
with lower maintainer reputation scores, etc., as my threat model dictates.

And likewise, this gives an opportunity for SAST tools and open source software security organizations to provide their services to the community at large.
I would love to be able to communicate our findings to the broad community regarding specific package trust levels-- I can't *ensure* the security of any given
software, but I can certainly say "Hey guys, we looked at this and didn't find anything." And depending on your risk tolerance, that might be the golden
stamp that you need to have a level of trust in some new package.

SCA accomplishes all of this concisely, and while it's relatively new in the grand scheme of the software supply chain, the concept of attestation isn't.
It's still immature in its adoption in many ecosystems, the Open Source Security Foundation continues to make strides towards implementing
attestation across a variety of domains. I realize I haven't explain what attestation was (directly) but I've actually been referring to this the entire time.

If we start associating specific build processes, security processes, etc., with a cryptographically sound method of proving that something exists as it purports,
e.g., "This was built by Github Actions with the following commit," then our trust level can increase in the open source ecosystem substantially. And if we start
examining these artifacts when we are developing and implementing open source software, we start to build a network of trust and security that is very difficult
to circumvent.

## Conclusion

I wrote a lot here-- this is a complex issue with a lot of valid solutions. OSS security remains in the limelight almost constantly, with vulnerabilities abound
and threat actors incredibly active in their efforts to taint the software supply chain. But we're not without answers.

Security professionals and software developers alike can increase involvement in the open source ecosystems not only through direct pull requests and code reviews, but contributions through code security engines.

And we're not without answers in managing these dependencies as well, which is certainly in the forefront of everyone's mind. Software Composition Analysis can turn
an extensive Software Bill of Materials into managable aggregate data that can then be actioned more concisely and with more concentrated effort than trying to do the
impossible task of reviewing every piece of code entering and leaving large projects.

One thing is for certain-- the xz backdoor highlights a number of processes that we can improve on in OSS security.
