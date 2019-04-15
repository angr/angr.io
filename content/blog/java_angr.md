---
title: "Experimental Java, Android, and JNI support in angr"
date: 2019-04-14T15:48:59-08:00
draft: true
authors: ["anton00b", "conand", "phate"]
tags: ["announcements", "tutorial", "extending_angr"]
preview: "angr can now symbolically execute Java code and Android apps!"
---

angr can now symbolically execute Java code and Android apps!
This also includes Android apps using a combination of compiled Java and native (C/C++) code.

This is the result of a multi-year effort by (in no particular order): Thorsten Eisenhofer ([thrsten](https://github.com/thrsten)), Sebastiano Mariani ([phate](https://github.com/phat3)), Ruoyu Wang ([fish](https://ruoyuwang.me/)), Antonio Bianchi ([anton00b](https://cs.uiowa.edu/people/antonio-bianchi)), and Andrea Continella ([conand](https://conand.me/)).

We implemented Java support by lifting the compiled Java code, both Java and DEX bytecode, leveraging our Soot python wrapper [pysoot](https://github.com/angr/pysoot).
Pysoot extracts a fully serializable interface from Android apps and Java code (unfortunately, as of now, it only works on Linux).
We then leverage the generated IR in a new angr engine able to run code in Soot IR: XXX.
This engine also automatically switches to executing native code if the Java code calls any native method using the JNI interface.

Together with the symbolic execution, we also implemented some basic static analysis, specifically a CFG (see: XXX, or maybe an exampleXXX).
Moreover, we added support for string constraints solving, modyfing claripy and using the CVC4 solver.

**WARNING: Java support is experimental!**
You might encounter issues while runing Java or Android apps. Please, report any bug!

## How to install
Enabling Java support requires few more steps than typical angr installation.
Assuming you installed [angr-dev](https://github.com/angr/angr-dev), activate the virtualenv and run:
```bash
# CVC4 is needed for String solving
pip install cvc4-solver
# install pysoot
git clone git@github.com:angr/pysoot.git
cd pysoot
pip install -e .
cd ..
# install the latest version of pysmt
pip uninstall pysmt
git clone https://github.com/pysmt/pysmt.git
pip install -e .
cd ..
```

## APK Analysis
Analyzing Android apps requires the Android SDK.
Typically, it is installed in `<HOME>/Android/SDK/platforms/platform-XX/android.jar`, where `XX` is the Android SDK version used by the app you want to analyze (you may want to install all the platforms required by the Android apps you want to analyze).

Unfortunately, as of now 

## Examples
There are multiple examples available: XXX

## Limitations and Future Work
As mentioned before **Java support is experimental!**

These are a few things that should be improved.
Welcome from the community is highly encouraged!
- Move away from pysoot or, at least:
-- Make it compatible with Windows, OSX, ...
-- Do not use Jython and Pickle to obtain the Soot IR in Python
- Implement more static analysis, including, data-flow, slicing, ... (WIP for now)
- Many many more simprocedures for the HUGE Java SDK
- ...?XXX



