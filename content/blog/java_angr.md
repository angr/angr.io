---
title: "Experimental Java, Android, and JNI support in angr"
date: 2019-04-14T15:48:59-08:00
draft: true
authors: ["anton00b", "conand", "phate"]
tags: ["announcements", "tutorial", "extending_angr"]
preview: "angr can now symbolically execute Java code and Android apps!"
---

`angr` can now symbolically execute Java code and Android apps!
This also includes Android apps using a combination of compiled Java and native (C/C++) code.

This is the result of a multi-year effort by (in no particular order): Thorsten Eisenhofer ([thrsten](https://github.com/thrsten)), Sebastiano Mariani ([phate](https://github.com/phat3)), Ruoyu Wang ([fish](https://ruoyuwang.me/)), Antonio Bianchi ([anton00b](https://twitter.com/anton00b)), and Andrea Continella ([conand](https://conand.me/)).

We implemented Java support by lifting the compiled Java code, both Java and DEX bytecode, leveraging our Soot python wrapper [pysoot](https://github.com/angr/pysoot).
`pysoot` extracts a fully serializable interface from Android apps and Java code (unfortunately, as of now, it only works on Linux).
![Pysoot Architecture](https://github.com/angr/pysoot/blob/master/pysoot_arch.png "Pysoot Architecture")

We then leverage the generated IR in a new angr engine able to run code in Soot IR: [engine.py](https://github.com/angr/angr/blob/master/angr/engines/soot/engine.py).
This engine is also able to automatically switch to executing native code if the Java code calls any native method using the JNI interface.

Together with the symbolic execution, we also implemented some basic static analysis, specifically a basic CFG reconstruction analysis.
Moreover, we added support for string constraint solving, modifying claripy and using the CVC4 solver.

Enabling Java support requires few more steps than typical angr installation.
Detailed installation instructions and a list of examples are available in the official [angr documentation](https://docs.angr.io/advanced-topics/java_support).

**WARNING: Java support is experimental!**
You might encounter issues while running Java or Android apps. Please, report any bug! Pull requests are very welcomed.

## Solving a CTF challenge
The challenge `javaisnotfun` from `iCTF 2017` contains a game, implemented as mixed Java/C code.
You can find its source code [here](https://github.com/angr/angr-doc/blob/master/examples/ictf2017_javaisnotfun/challenge/src.tar?raw=true) and a writeup (in Chinese) [here](https://ctftime.org/writeup/5964).

The challenge starts with a challenge-response game in which 5 random numbers are shown to the user, and the user has to reply with 3 numbers.
Solving five rounds of the game allows the attacker to trigger the challenge vulnerability.

We will now focus on how to solve one round of the game using `angr`.
The complete `angr` code is available [here](https://github.com/angr/angr-doc/tree/master/examples/ictf2017_javaisnotfun).

A typical approach would require reversing the Java code and the native code used to implement the game.
However, if you are lazy, you can just use `angr` to, starting from the 5 numbers outputted by the game, automatically compute the 3 numbers of the solution.

This is the source code implementing one round of the game
```Java
Random rnd = new Random();
int c1,c2,c3,c4,c5;
c1 = rnd.nextInt(100);
c2 = rnd.nextInt(100);
c3 = rnd.nextInt(256);
c4 = rnd.nextInt(10);
c5 = rnd.nextInt(10);
print("These are your unlucky numbers:");
print(c1);
print(c2);
print(c3);
c3 <<= 8;

switch(c4){
case 0:
  c3 = c3 * 2 + 3;
  break;
case 1:
  c3 = c3 * 7 + 8;
  break;
case 2:
  c3 = c3 * 3 + 1;
  break;
case 3:
  c3 = c3 * 5 + 3;
  break;
case 4:
  c3 = c3 * 2 + 9;
  break;
case 5:
  c3 = c3 * 9 + 1;
  break;
case 6:
  c3 = c3 * 6 + 2;
  break;
case 7:
  c3 = c3 * 5 + 4;
  break;
case 8:
  c3 = c3 * 8 + 2;
  break;
case 9:
  c3 = c3 * 4 + 2;
  break;
}
switch(c5){
case 0:
  c3 = magic0(c3);
  break;
case 1:
  c3 = magic1(c3);
  break;
case 2:
  c3 = magic2(c3);
  break;
case 3:
  c3 = magic3(c3);
  break;
case 4:
  c3 = magic4(c3);
  break;
case 5:
  c3 = magic5(c3);
  break;
case 6:
  c3 = magic6(c3);
  break;
case 7:
  c3 = magic7(c3);
  break;
case 8:
  c3 = magic8(c3);
  break;
case 9:
  c3 = magic9(c3);
  break;
}
print(c4);
print(c5);

//System.err.println("expected: " + String.valueOf(c1+2)+"|"+String.valueOf(c2*3+1)+"|"+String.valueOf(c3));
if(! (getInt() == c1 + 2)){
  gameFail();
}
if(! (getInt() == magic000(c2))){
  gameFail();
}
if(! (getInt() == c3)){
  gameFail();
}
```

```C
JNIEXPORT int JNICALL Java_NotFun_magic000(JNIEnv *env, jobject thisObj, jint n) {
   return n*3 + 1;
}

JNIEXPORT int JNICALL Java_NotFun_magic0(JNIEnv *env, jobject thisObj, jint n) {
   return (n<<1) + 4;
}
JNIEXPORT int JNICALL Java_NotFun_magic1(JNIEnv *env, jobject thisObj, jint n) {
   return (n<<4) + 3;
}
JNIEXPORT int JNICALL Java_NotFun_magic2(JNIEnv *env, jobject thisObj, jint n) {
   return (n<<3) + 2;
}
JNIEXPORT int JNICALL Java_NotFun_magic3(JNIEnv *env, jobject thisObj, jint n) {
   return (n<<2) + 3;
}
JNIEXPORT int JNICALL Java_NotFun_magic4(JNIEnv *env, jobject thisObj, jint n) {
   return (n<<2) + 1;
}
JNIEXPORT int JNICALL Java_NotFun_magic5(JNIEnv *env, jobject thisObj, jint n) {
   return (n>>2) + 3;
}
JNIEXPORT int JNICALL Java_NotFun_magic6(JNIEnv *env, jobject thisObj, jint n) {
   return (n>>3) + 3;
}
JNIEXPORT int JNICALL Java_NotFun_magic7(JNIEnv *env, jobject thisObj, jint n) {
   return (n>>1) + 3;
}
JNIEXPORT int JNICALL Java_NotFun_magic8(JNIEnv *env, jobject thisObj, jint n) {
   return (n>>4) + 7;
}
JNIEXPORT int JNICALL Java_NotFun_magic9(JNIEnv *env, jobject thisObj, jint n) {
   return (n>>1) + 1;
}
```
Java code and native C code communicate using the JNI interface.

Let's create, using `angr`, a function able to compute the 3 response values, given the 5 random challenge values.
First of all we need to create an `angr` project.
```Python
binary_path = os.path.join(self_dir, "bin/service.jar")
jni_options = {'jni_libs': ['libnotfun.so']}
project = angr.Project(binary_path, main_opts=jni_options)
```
As you can see, we manually specify that the `jar` file uses a native library `linotfun.so`.


We then set up a few hooks.
Since these hooks are in Java, we specify their addresses using the class `SootMethodDescriptor`.
```Python
project.hook(SootMethodDescriptor(class_name="java.util.Random", name="nextInt", params=('int',)).address(), Random_nextInt())
project.hook(SootMethodDescriptor(class_name="java.lang.Integer", name="valueOf", params=('int',)).address(), Dummy_valueOf())
project.hook(SootMethodDescriptor(class_name="NotFun", name="print", params=('java.lang.Object',)).address(), Custom_Print())
project.hook(SootMethodDescriptor(class_name="NotFun", name="getInt", params=()).address(), Custom_getInt())
```

Then, we set up the symbolic execution entry point.
Specifically, we want to start the symbolic execution from the Java method called `game()`:
```Python
game_method = [m for m in project.loader.main_object.classes['NotFun'].methods if m.name == "game"][0]
game_entry = SootMethodDescriptor.from_soot_method(game_method).address()
entry = project.factory.blank_state(addr=game_entry)
simgr = project.factory.simgr(entry)
```

To handle the challenge-response, we create two fake files keeping track (symbolically) of what the program prints (the 5 challenge numbers) and what the user inserts (the 3 response values).
See the [full solution](https://github.com/angr/angr-doc/tree/master/examples/ictf2017_javaisnotfun) for details.

Finally, we start symbolically executing the program step-by-step.
We prune paths reaching the `gameFail()` method, while we stash paths solving one round of the game (formally, reaching basic block 30 of the method `game()`).
```Python
print("="*10 + " SYMBOLIC EXECUTION STARTED")
while(len(simgr.active)>0):
    simgr.step()
    print("===== " + str(simgr))
    print("===== " + ",".join([str(a.addr) for a in simgr.active if type(a.addr)==SootAddressDescriptor]))

    # If we reach block_idx 30, it means that we solved 1 round of the game --> we stash the state
    # If we reach the gameFail() method, it means that we failed --> we prune the state
    simgr.move('active', 'stashed', lambda a: type(a.addr) == SootAddressDescriptor
               and a.addr.method == SootMethodDescriptor("NotFun", "game", ()) and a.addr.block_idx == 30)
    simgr.move('active', 'pruned', lambda a: type(a.addr) == SootAddressDescriptor
               and a.addr.method == SootMethodDescriptor("NotFun", "gameFail", ()))

print("="*10 + " SYMBOLIC EXECUTION ENDED")
assert len(simgr.stashed) == 1
win_state = simgr.stashed[0]
numeric_solutions = []
for s in solutions:
    es = win_state.solver.eval_atmost(s, 2)
    assert len(es) == 1
    numeric_solutions.append(es[0])
```
`numeric_solutions` will contain the 3 response values.


## Limitations and Future Work
As mentioned before **Java support is experimental!**

These are many things that should be improved, for instance:
- Move away from `pysoot` or, at least:
  - Make it compatible with Windows, OSX, ...
  - Do not use Jython and Pickle (but something more efficient, such as `protobuf`) to obtain the Soot IR in Python
- Implement more static analyses, including, data-flow, slicing, ... (this is currently work-in-progress)
- Many many more simprocedures to model the _HUGE_ Java SDK
- ...

_Welcome from the community is highly encouraged! Pull requests are very welcomed!_
