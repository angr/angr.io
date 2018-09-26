---
title: "angr 8 release"
date: 2018-09-26T14:14:02-07:00
draft: false
authors:
  - lockshaw
tags:
  - release
  - angr8
preview: "Python 3 migration, Clemory refactor, CFGFast optimization, and more"
---

The angr team is happy to announce the release of a new major version of angr, angr 8!
angr 8 brings a variety of large and potentially breaking improvements, as well as a bunch of smaller bugfixes.
The highlights are listed below, but we also recommend checking the angr 8 section of the [Changelog](https://docs.angr.io/) for a list of the major changes and the [Migration Guide](https://docs.angr.io/MIGRATION.html) for help in migrating your project to angr 8.

As always, to contact the angr team please reach out on [our slack](http://angr.slack.com).
You can request an invitation [here](/invite).
For more information on how to get involved with the angr project, see [here](/#contact).

# Highlights:

## Python 3 Migration

The largest change in angr 8 is the migration to Python 3. **As of angr 8, angr will be dropping all Python 2 support and moving to Python 3**.
For now, we will be targeting Python 3.5, with plans to eventually move to 3.6.
The last Python 2-compatible angr release will be version [GET FROM AUDREY].
If you need any help migrating your code to Python 3, please see the [Migration Guide](https://docs.angr.io/MIGRATION.html).

## Clemory API Refactor

With the upgrade to Python 3 come a number of changes to the Clemory API (`project.loader.memory`) around replacing the Python 2 string type with Python 3's `bytes`.
This should make working with Clemory easier, as well as yield significant performance benefits.
While most of the new API should be relatively easy to migrate to, if you are using the `cbackers` or `read_bytes_c` functions, the changes may be a little more complicated.
For a detailed explanation of the changes, see the [Migration Guide](https://docs.angr.io/MIGRATION.html). Thanks to **@rhelmot** for the refactor!

For those interested, the commit with most of the changes can be found [here](https://github.com/angr/cle/commit/d1b518736e48abe67cfdf0fc1b18f09cf88f17d9).

## Up to 5x Speedup in CFGFast

Driven by the need to recover the CFG of a large blob, the angr team has significantly improved the performance of CFGFast.
Amongst other things, angr is now able to lift blocks without converting their statements into Python objects, perform more of the analysis in C, and avoid lifting any basic block more than once.
All combined, we've seen this give a more than 5x speedup on large binaries!
For changes and benchmarking details, see [PR #1092](https://github.com/angr/angr/pull/1092).
Thanks to **@KevOrr** for the binary that motivated the changes and **@fish** for the optimizations!
