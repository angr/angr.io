---
title: "Experimental Java, Android, and JNI support in angr"
date: 2019-04-16T19:41:03-08:00
draft: true
authors:
  - anton00b
  - conand
tags:
  - tutorial
  - extending_angr
preview: "angr can now symbolically execute Java code and Android apps!"
---

angr can now symbolically execute Java code and Android apps!
This includes java code and Android apps using a combination of compiled Java code and native (C/C++) code.

This is the result of a multi-year effort by (in no particular order): Thorsten Eisenhofer, Sebastiano Mariani, Ruoyu (Fish) Wang, Antonio Bianchi, and Andrea Continella. (XXX links)

This has been implemented by lifting the compiled Java code (Java or DEX bytecode) using Soot (specifically, the python wrapper: pysoot).
Pysoot extract a fully serialiable (just use `pickle`) interface from Android apps and Java code (unfortunately, as of now, it only works on Linux).
The generated IR is then used by a new angr engine able to run code in Soot IR: XXX.
This engine automatically switches to executing native code if the Java code calls any native method (using the JNI interface).

Together with the symbolic execution, also some static analysis has been implemented in angr, specifically a CFG (see: XXX, or maybe an exampleXXX).
To solve string related constraints a string solver (CVC4) is used.

**WARNING: Java support is experimental!**
Do not expect to be able to run Java code or Android apps out of the box!

## How to install
Install angr using the angr-dev repository in a virtualenv.
In the same virtualenv run:
```
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



