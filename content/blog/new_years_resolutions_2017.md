---
title: "angr's new year resolutions"
date: 2018-01-15T15:35:26-08:00
draft: false
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

1. **Training:**
Last month, we ran an all-day angr tutorial at ACSAC.
The response from this was very positive, and we'll be looking at more venues to run these sorts of classes.
If you're interested in this, get in touch!

2. **An angr "course":**
Another idea on the TODO list is a course that gradually introduces angr concepts.
Again, we started down this road with the ACSAC tutorial, and some of the
[resulting exercises](https://github.com/angr/acsac-course) can be reused for a comprehensive course.
This is also something that seems to have community interest, with
[contributions](https://github.com/angr/angr-doc/pull/113) beginning to roll in.

3. **More blog-post micro-examples:**
Many of our examples are CTF challenges.
This is good because it shows angr working in often-adversarial conditions, but it also means that many of the examples are too
confusing.
We plan to make a series of smaller examples, that can be blogged and explained, that demonstrate specific angr features or phi
losophies, similar to Miasm's and Triton's blog examples.
Hopefully, this will help new users approach angr without too much pain.

4. **Better support channels:**
Currently, angr support happens mainly through IRC, GitHub issues, and the mailing list.
Unfortunately, with the way the world has been heading, most of us (shamefully) spend very little time actually looking at our
IRC clients, and instead mostly hang out on various slacks.
In fact, from the very early days of angr, we have had an [angr slack](https://angr.slack.com) for coordination betw
een us all at UCSB.
Now, we are opening this up to the world (to get a slack invite, go [here](/invite)), and making it the prima
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

## Contributions

A second area for us to improve is the ease with which people can make contributions to the project.
Currently, angr development is carried out in two different places: we do development on our internal gitlab infrastructure, and
then periodically synchronize it to GitHub.
With this, until recently, all of our CI testing was done on gitlab.
This made taking PRs very complicated: first, we would have to review all the code (because we'd CI it internally),
then synchronize it to gitlab, then run the CI, then explain to contributors why it failed, and repeat the process again.
This resulted in hugely delayed PR merges.
Additionally, because long-running development branches would happen on gitlab, out of the public eye, the project probably looks
dead for much of the time, with random crazy push activity when we synchronize things.
Worse, during such processes, we would be unable to accept PRs, as it'd cause merging the long-running branch in would
be a nightmare.
In fact, this is *currently* happening, and many PRs are sitting around until the currently huge development effort
(about which I'll talk below) concludes.

Our plan is to solve this through the following:

1. **Moving our testing to TravisCI:**
This is currently underway, with most angr sub-projects now being tested on Travis, and more to come.
This will allow us to avoid having to pull in PRs into gitlab for testing, and will give contributors immediate feedback on their PRs.
2. **Moving our development to GitHub:**
Once testing fully works on TravisCI, we will move our development fully to gitHub. Throughout the last year, we've been working to make angr more modular, so that our research can be implemented *outside* of angr, using angr as an actual framework.

With this (almost) done, and CI (almost) on Travis, there is (almost) nothing stopping us from developing on GitHub directly.

Once we move to GitHub, the PRs can be accepted quickly, and the project continuously looks alive from the outside,
we think (hope) that community enthusiasm and contributions will increase.

## Applicability

Currently, angr is one of the most powerful binary analysis frameworks out there.
We support the 32-bit and 64-bit variants of x86, ARM, MIPS, and PPC,
and offer a range of static analyses along with a powerful symbolic execution engine.
This has allowed angr to be used as the base for an [automated ROP generator](https://github.com/salls/angrop),
a [binary patching engine](https://github.com/angr/patcherex),
a [next-generation fuzzer](https://github.com/shellphish/driller),
an [auto-exploitation engine](https://github.com/shellphish/rex),
and other exiting stuff.

However, we'd like to drive it further.

The long-running development branch alluded to earlier is an effort that we're undertaking
to make angr expandable to other targets.
For example, using LLVM, angr could analyze source code and, using SOOT, Java bytecode.
Additionally, developments in the [QEMU world](https://lists.nongnu.org/archive/html/qemu-devel/2016-11/msg04847.html)
from rev.ng might allow us to use QEMU's TCG to expand support to many additional binary platforms.
Essentially, we're working to make angr more or less independent of the specific backend translation and execution engine used.
We have the following execution engines on our roadmap:

+ **VEX (already supported):** This is what angr currently uses to analyze binary code.
+ **Python hooks (already supported):** We already support the ability to provide manual summaries of code, in the form of python functions.
+ **Unicorn engine (already supported):** We use Unicorn Engine as an execution engine to speed up angr's analysis when dealing with concrete data.
+ **SOOT (imminent):** We plan to use SOOT to expand angr's capabilities and allow it to analyze Java bytecode.
+ **LLVM (future):** Between VEX, SOOT, and LLVM, angr's analyses would be applicable to almost any type of program out there.
+ **Miasm (future):** Miasm has a very cool dynamic sandbox that would be very useful to leverage in a similar way to how we currently leverage Unicorn. Unlike Unicorn, however, Miasm also has <i>syscall support</i>. We could hook into this to supplement angr's environent support (especially for Windows binaries), at the cost of (as Miasm's sandbox is purely concrete) having to concretize symbolic data that would be passed into this sandbox.
+ **QEMU User, GDB, or Valgrind (far future):** Similarly to Miasm (though perhaps less contained), qemu-user implements a lot of environmental support that could be leveraged. Unfortunately, QEMU is notoriously hard to expand and plug into, and most projects that do end up getting stuck with an quickly-outdated version of QEMU as their base. Likewise, we could use GDB or Valgrind for a less architecture-flexible version of this, but they have their own issues as well.

We're currently wrapping up the underlying changes (including converting the VEX, hooks, and Unicorn Engine stuff), and they'll soon be merged (and pushed to GitHub).
Once that's done, we'll likely start working on SOOT.
If people are interested in working on some of the other potential engines on the list, let us know!

## Summary

2017 is going to be an exciting year for angr, and we hope you'll be with us through it all.
Come join us on slack, send some PRs, and let's usher in the next generation of binary (and more!) analysis.
