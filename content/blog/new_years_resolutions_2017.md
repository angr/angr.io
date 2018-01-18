---
title: "angr's new year resolutions"
date: 2018-01-15T15:35:26-08:00
draft: true
authors: ["zardus"]
tags: ["announcement"]
preview: "After a busy 2016, angr is ready to make some new year resolutions!"
---

From academic research to the Cyber Grand Challenge, angr has had a busy 2016!
Now that the angr team is (mostly) back from the holidays, it's time to plan a busy and successful 2017.
For this year, we are looking at three major areas of improvement: usability, contributability, and applicability.

## Usability
First, we would like to make angr more approachable and usable by the community.
We recognize that, in its current state, angr is *very* hard to get started with.
Currently, we try to provide documentation (both as [prose](http://docs.angr.io) and as [API references](http://api.angr.io),
and [examples](https://github.com/angr/angr-doc/tree/master/examples), but this fails to get across many
of the subtleties of binary analysis in general and angr specifically.
Because of this, much of the power of angr is completely unknown to the community, with a depressing amount of people using angr
just to `find` and `avoid` addresses in CTF challenges.
We have a few ideas to make this better:

1. Training.
Last month, we ran an all-day angr tutorial at ACSAC.
The response from this was very positive, and we'll be looking at more venues to run these sorts of classes.
If you're interested in this, get in touch!

2. An angr "course".
Another idea on the TODO list is a course that gradually introduces angr concepts.
Again, we started down this road with the ACSAC tutorial, and some of the [resulting exercises](https://github.com/angr/acsac-course)
can be reused for a comprehensive course.
This is also something that seems to have community interest, with [contributions](https://github.com/angr/angr-doc/pull/113) beginning to roll in.

3. More blog-post micro-examples.
Many of our examples are CTF challenges.
This is good because it shows angr working in often-adversarial conditions, but it also means that many of the examples are too
confusing.
We plan to make a series of smaller examples, that can be blogged and explained, that demonstrate specific angr features or phi
losophies, similar to Miasm's and Triton's blog examples.
Hopefully, this will help new users approach angr without too much pain.

4. Better support channels.
Currently, angr support happens mainly through IRC, github issues, and the mailing list.
Unfortunately, with the way the world has been heading, most of us (shamefully) spend very little time actually looking at our
IRC clients, and instead mostly hang out on various slacks.
In fact, from the very early days of angr, we have had an [angr slack](https://angr.slack.com) for coordination betw
een us all at UCSB.
Now, we are opening this up to the world (to get a slack invite, go [here](../invite.html)), and making it the prima
ry real-time angr support channel.
We definitely understand that this is going to be a controversial move: people love IRC, and some enjoy other platforms (gitter
, mattermost, etc).
However, the fact is that we're already on slack, and bringing you to us is going to work better than trying (and likely failin
g) to bring us to you.
As a reminder, slack can be accessed through an
[IRC gateway](https://get.slack.help/hc/en-us/articles/201727913-Connect-to-Slack-over-IRC-and-XMPP)
The freenode `#angr` channel will continue to exist, but please keep in mind that responses there will be much more hit and miss
than on slack.

Of course, the limiting factor with usability and support is time.
As a group of students, we have many high-priority demands on our time, and documentation and usability often takes a back seat.
As in the case of the course PR, we hope this time pressure will be partially mitigated by the community.

## Contributions.
A second area for us to improve is the ease with which people can make contributions to the project.
Currently, angr development is carried out in two different places: we do development on our internal gitlab infrastructure, and
then periodically synchronize it to github.
With this, until recently, all of our CI testing was done on gitlab.
This made taking PRs very complicated: first, we would have to review all the code (because we'd CI it internally),
then synchronize it to gitlab, then run the CI, then explain to contributors why it failed, and repeat the process again.
This resulted in hugely delayed PR merges.
Additionally, because long-running development branches would happen on gitlab, out of the public eye, the project probably looks
dead for much of the time, with random crazy push activity when we synchronize things.
Worse, during such processes, we would be unable to accept PRs, as it'd cause merging the long-running branch in would
be a nightmare.
In fact, this is *currently* happening, and many PRs are sitting around until the currently huge development effort (
about which I'll talk below) concludes.

