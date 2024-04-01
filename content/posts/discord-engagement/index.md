---
title: "Discord Engagement"
date: 2023-07-13T20:15:48-05:00
tags: ['social media','open source']
summary: "Discord is the most populated live chat interaction platform on the internet. Let's take some time to discuss how we could use that to engage open source communities and enterprise user bases more effectively, and discuss some of the public perceptions that surround Discord."
draft: false
---

I often find myself interacting with individuals on a formal basis and discussing how Vipyr Security does what it does. From the random interested Discord user to the Twitter DM, to professionals in legitimate organizations. It very much strikes me as slightly shameful to admit that we utilize Discord to conduct our operations. I'm not sure why; it offers plenty of useful tools for moderating communities, integrating tools and notifications, role based access, etc. But I'd be remiss to say that I don't hang my head dejectedly a bit when I remark that we've built an entire Security Operations Center with Discord as the nucleus. So let's talk about it...

## Role Based Access

One of the major appeals to Discord is role based access. Internal cybersecurity discussions can be unfit for public consumption, yet not require a particularly strong level of legitimate security. While it's not critical that things like our YARA ruleset or internal codebases remain internal, it's certainly something that we benefit from heavily during the development process. I say that to more qualify the opinion that-- I understand Discord isn't a secure communications platform, but the level of security that it does offer is likely more than enough for most open source communities and projects.

Rolling your own role based access or utilizing other platform is certainly an option, but with it comes a barrier to entry. Not everybody is willing to download Slack, and IRC has been on its last leg for the last two decades. (Will it ever die?) Discord itself has over 150 million monthly users according to [Influencer Marketing Hub](https://influencermarketinghub.com/discord-stats/). Slack, by comparison, is predicted to have 32.3 million in 2023 by [DemandSage](https://www.demandsage.com/slack-statistics/). By sheer statistics alone, it's more likely that an individual that you may wish to reach organizationally may have a Discord, so long as we ignore some potential factors such as age-groupings.

Cybersecurity (and at a more fundamental level, the computer science and information technology fields) tend to spend more time online in comparison to other fields. As a result, I think it stands to reason that a large portion of these individuals, as a result, will likely also maintain a Discord account of some sort, or at least be reasonably aware of it.

What does this mean? Individuals *tend* towards knowing how to manipulate Discord as well.

## Application Integration

Discord features a full suite of user interactivity tools and application development API's. Most of these tools are utilized in the context of simple moderation bots. But what if we piped a constant feed of malware into a community full of malware analysts? Likewise, what if we templatized reporting through the Discord API to facilitate live interaction and ease of use of analyzing this malware?

Shockingly, it works pretty darn well. Being able to add functionality to a user-friendly front end that isn't based on browsers or applications, but is delivered in a user-defined format to the very area where user interactions are occurring is remarkably useful. It encourages constant attention, and facilitates cooperation and ease of use.

It allows for expansion of features without redelivering software, and the best selling point-- it's absolutely free. Being able to center your user base, your contributors and your interactions to a single, clearly defined point and integrating development processes into Discord itself through the API, through webhooks, through bots, through applications, etc., is highly effective at both creating and maintaining interest.

## Broaching the User Barrier

One thing I lament in the Python community is the level of seclusion that some core Python communities keep. Largely, the most intelligent discussions do not occur in a widely open forum. Instead, they often seclude themselves to the [Python.org Discourse](https://discuss.python.org/) forums, or via Github interactions. While these may conventionally be open, it's unlikely that individuals that are looking for information are going to enumerate these venues first. I would cite the 229 posts in the last month on the Python Discourse as evidence that it simply isn't a primary resource.

So what should the primary user interaction venue be, exactly? Well, I would purport the following: This is transformational. If you hold some sort of knowledge to something, and desire that knowledge to be spread or interacted with, it's largely your responsibility to place that information into public purview. To the credit of Core Python communities, and in general, communities as a whole-- the adoption of Discord as a community outreach and discussion platform for legitimate businesses is gaining momentum. Where internal discussions have previously been the standard, the level of interaction between enterprise and individual is steadily increasing.

I believe we should celebrate live chat platforms and strive to reach individuals on the platforms *they* interact with. Whether that be Discord, or whatever comes next, it is fundamental both for organizations seeking open source contribution or discussion, or even just candid user feedback and interaction, to follow where their communities are most prevalent at the time. It's not effective for you to generate an IRC channel on Freenode if nobody is going to interact with you in that channel, and it's slightly disingenuous to imply that your organization is open to feedback when that feedback sits in a portion of the internet that sees little use.

## So Why is it Shameful?

Harkening back to my initial point, I still feel a bit of dejectedness when I mention that we utilize Discord primarily to organize our community. And I'm truly not sure why; it ticks all the boxes. The integrations it offers are pivotal to how we've laid out our detections, the ability to modify how we interact with our API by convenience of bot commands and automated assistants has been great to engage our userbase and encourage community participation.

Perhaps it's the reputation that Discord holds, the idea that it's a gathering place for gamers. Or the numerous communities, both public and private, that participate in matters such as [leaking classified information](https://www.washingtonpost.com/national-security/2023/04/12/discord-leaked-documents/) or the proliferation of adult content and malicious software. But these don't strike me as particularly unique to the Discord platform. I watched a [Linus Tech Tips video](https://www.youtube.com/watch?v=ynmnvT_h8BE) recently on the idea that Discord itself could market towards enterprises as they lamented the change of user discriminators.

I hope that one day soon, informing professionals and industry thought leaders that we've built a SOC-in-a-box that secures the Python ecosystem with Discord as it's central interaction point isn't something that I'm ashamed of-- at 500 packages detected and removed so far, it's a proven recipe that is deadly effective. But for now, I'll lament quietly that the social stigma of a community based on Discord could be perceived as unprofessional or illegitimate.

## Closing Remarks

I'm not really sure where I'm going with this-- it's my blog post, I can do what I want I guess. But I do think it's a fairly radical idea to center an enterprise where your community is rather than internally with outreach towards your community. If Discord is the "hot thing" now, then Discord is where you should be. If in the future Mastadon, or Threads, or Reddit takes off, then that is where you should be. Engaging the community is a fundamental aspect of both open source projects/communities and business enterprises, and I think we would stand to benefit greatly as an open-source ecosystem if we adopted these ideals.
