---
title: "symbion: fusing concrete and symbolic execution"
date: 2018-11-20T15:48:59-08:00
draft: false
authors: ["degrigis", "subwire", "r0rshark"]
tags: ["announcements", "symbion"]
preview: "Learn how to symbolically execute real-world binaries by fusing concrete and symbolic execution"
---

Today we are going to talk about an exciting new feature that we have recently released on [angr's master](https://github.com/angr/angr/commit/fe20116e8dc2aef94d0849439ff9f12a39000dfe): Symbion, a brand new exploration technique aimed to overcome some of the complexities that real-world programs exhibit and that can't or are not currently modeled in our symbolic engine.

# Motivation

When we leverage a symbolic execution tool such as angr to analyze a program, we depend on a model of the operating system and libraries to make the analysis tractable ( in fact trying to symbolically execute everything would lead immediately to a state explosion).
However, there are a lot of libraries and system calls out there, and we cannot hope to model them all.  In the case that a program requires an unmodeled procedure, we generally either lose precision, encounter state explosion or spend a lot of time developing a *SimProcedure*. For real-world programs, this can become a huge barrier to a useful analysis.

**Instead of modeling, Symbion levereges a concrete execution of a program to support the symbolic analysis**.

Analysts may wish to symbolically reason about control flow of a program between two program points B and C, but can't even execute from point A to point B due to unmodeled behaviors. With Symbion, they can execute concretely up to point B, switch into angr's symbolic context, and compute the program input needed to reach point C.  The solution obtained by angr can then be written into the program's memory and by resuming the concrete execution reaching beyond point C.

{{< img "Symbion workflow" "symbion_workflow.jpg" >}}

In academia, previous works have explored similar ideas with projects like [Mayhem](https://users.ece.cmu.edu/~dbrumley/pdf/Cha%20et%20al._2012_Unleashing%20Mayhem%20on%20Binary%20Code.pdf), [AVATAR](http://s3.eurecom.fr/docs/bar18_muench.pdf) and [S2E](https://cseweb.ucsd.edu/~dstefan/cse291-fall16/papers/s2e.pdf). We leverege some of the interesting ideas implemented in these projects with the aim of making a hybrid concrete/symbolic approach that is easy to use and flexible enough to build upon.

Our main design goals are:

1. Couple the concrete environment to the symbolic environment, without depending on what the concrete environment is and letting users to implement new *ConcreteTarget* ( the object responsible to control the concrete execution of the program in the concrete environment ) through a well-defined and simple interface.

2. Allow context switches between concrete and symbolic (and vice versa), without expensive transfers of state.

3. Allow changes to the concrete state, to enable further exploration based on the results of angr analyses.

With these goals in mind, we have worked to create Symbion, while minimizing the changes to the overall angr environment and workflow.

# System overview

{{< img "Symbion main components" "symbion_sys_overview.png" >}}

The first thing we need to do when performing an analysis is creating the concrete environment we wish to use.  Symbion adds the notion of a *ConcreteTarget*, a generic abstraction for any execution environment that defines simple memory, register, and execution control interactions.

For example, to connect to a gdbserver:

```python
from angr_targets import AvatarGDBConcreteTarget

# Start a gdbserver instance
subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,'/bin/ls'),
                  stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE, shell=True)

# Instantiation of the AvatarGDBConcreteTarget
avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP,
                                    GDB_SERVER_PORT)
```

While here we use a GDB concrete target, it is totally possible to implement new targets ( like full-system emulators, hardware via an attached debugger, a Windows debugger,... ) by implementing a very simple interface:

```python
   # read 'length' bytes from address in the concrete process memory
   def read_memory(self, address, length, **kwargs):

   # write 'data' at 'address' inside the concrete process memory
   def write_memory(self, address, data, **kwargs):

   # read specified 'register' data
   def read_register(self, register, **kwargs):

   # write 'value' inside specified 'register'
   def write_register(self, register, value, **kwargs):

   # set a breakpoint at 'address'
   def set_breakpoint(self, address, **kwargs):

   # remove breakpoint at 'address'
   def remove_breakpoint(self, address, **kwargs):

   # get information about memory mapping of the target process
   def get_mappings(self):

   # resume the execution of the concrete process
   def run(self):

   # force stop of the concrete execution
   def stop(self):
```

The attentive reader may notice that this API bears a striking similarity to the [interface](https://github.com/avatartwo/avatar2/blob/master/avatar2/targets/target.py) used by the [AVATAR](http://s3.eurecom.fr/docs/bar18_muench.pdf) target-orchestration framework; this is intentional, and we inherit target code and capabilities from [AVATAR](http://s3.eurecom.fr/docs/bar18_muench.pdf)'s collection of pluggable targets.

Next, we need to create the angr environment.  This is done in the usual way, but specifying that a *ConcreteTarget* is to be used:

```python
# Creating an angr Project by specifying that we are going to use a concrete target
p = angr.Project(binary_x64, concrete_target=avatar_gdb,
                 use_sim_procedures=True)
```

The primary user-facing component of Symbion is its *ExplorationTechnique*, which works similarly to the other available techniques. This allows us to execute the program until a certain address is reached, or any number of other conditions.

Translating this idea into the script, let's say we want to reach ```0x4007a4```:

```python
# Create the state at the beginning of the program
entry_state = p.factory.entry_state()

# Create a simulation manager to hold this exploration
simgr = p.factory.simgr(entry_state)

# Explore the program concretely until we reach 0x4007a4
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x4007A4]))

exploration = simgr.run()
```

While this seems simple, a lot of the complexity of Symbion is hidden in the transition between the concrete and the symbolic contexts.
The whole magic occurs through a new angr execution engine (*SimEngineConcrete*) and an accompanying *Concrete state plugin* ( these are complex enough to warrant their own blog post and will be discussed later ).
For now, it suffices to say that at the end of its execution (when we have reached the target address), the *SimEngineConcrete* returns a *SimState* reflecting the current state of the concrete target.

{{< img "Interaction with ConcreteTarget" "symbion_ct_interaction.gif" >}}

However, this synchronization does _not_ need to copy any memory; during the synchronization with the concrete target, we modify the state's memory backend such that reads are lazily redirected to the underlying concrete memory.

{{< img "Lazy memory redirection" "symbion_lazymem.jpg" >}}

We are again free to perform any analysis we wish.  Note that while this state forwards memory reads to the underlying concrete target, writes are _not_ forwarded, and will remain only in this symbolic state, until they are concretized and applied to the target.
Concretization is triggered by the use of the *concretize* argument passed to Symbion. We only need to supply a list of addresses, and the variable we wish to solve for.

```python
# Instructing angr to use the Symbion exploration technique to bring the
# concrete process to the address 'BINARY_EXECUTION_END'
simgr.use_technique(angr.exploration_techniques.Symbion(find=[BINARY_EXECUTION_END],
                                  concretize = [(address,my_variable)]))
```

# Example

For this example, we are going to use a homemade toy binary (a 64-bit Linux ELF) that will make decisions about the execution based on an internal hardcoded configuration.
The binary has also been packed with [UPX](https://upx.github.io/) in order to hinder as much as possible the analysis with angr.

Disclaimer: this homemade "malware" is definitely not a real-world case scenario, but its level of complexity is perfectly suited for showing how Symbion works. We are planning to show you real-world cases in future blog posts!

Before starting make sure you cloned the [angr-targets](https://github.com/angr/angr-targets) and you installed it in your python virtualenv.

Let's begin! :D

First thing first, let's get familiar with our binary.
You can get a [copy](https://github.com/angr/binaries.git in tests/x86_64/packed_elf64) from the angr [binaries](https://github.com/angr/binaries) repository

By executing it, you have a surprise:

```bash
[+] Parsing malware configuration
[+] Virtual environment detected!

```

Seems that we have an evasive behavior here!
We leave the reversing of the binary and the discovering of its original entry point (OEP) as an exercise to the reader, but for the sake of our example, we'll spoil it: ```0x400b95```.
We then execute the binary until we reach the OEP, using the procedure outlined above, and construct the control-flow graph of the unpacked binary.
By looking at the CFG at the OEP we can easily see 4 possible behaviors of the binary:

{{< img "Malware CFG and its behaviors" "symbion_ex1.png" >}}

All this behavior depends on the hardcoded configuration mentioned at the beginning. We can spot the usage of this configuration at the address ```0x400cd6```: the point where the first decision is taken from the binary.
Seems that with the default hardcoded configuration we are following the yellow path!

{{< img "Default behavior with current configuration" "symbion_ex2.png" >}}

Now, as analysts, our job here is to study this binary's malicious behavior, and how it is triggered.  We see some nasty secondary payload dropped starting in the basic block at ```0x400d6a```; how do we get there? And what about the basic block ```0x400d99```? Well, this is what symbolic execution is good for!

The idea is to let the binary unpack itself and reach concretely the position where the first decision is taken ( the address ```0x400cd6``` ), synchronize the state inside angr, define as symbolic the configuration buffer, explore symbolically and resume the program as we whish given the solution provided by angr!

However, this binary is packed, and the memory there will be overwritten by the unpacking process.  Software breakpoints, like the ones used by GDB, will be overwritten as well.
Instead, we manually reverse-engineer the binary and determine that we can execute from the beginning of the program until ```0x85b853``` to have a new stub available at ```0x45b97f``` and eventually wait for 4 breakpoint hits to this address to have our unpacked code at ```0x400cd6```.

Let's put this into code!

```python
import subprocess
import os
import nose
import avatar2 as avatar2

import angr
import claripy
from angr_targets import AvatarGDBConcreteTarget


# First set everything up
binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries',
                                          'tests','x86_64',
                                          'packed_elf64'))

# Spawning of the gdbserver analysis environment
print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x64))
subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x64),
                  stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE,
                  shell=True)

# Instantiation of the AvatarGDBConcreteTarget
avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64,
                                     GDB_SERVER_IP, GDB_SERVER_PORT)

# Creation of the project with the new attributes 'concrete_target'
p = angr.Project(binary_x64, concrete_target=avatar_gdb,
                             use_sim_procedures=True)

entry_state = p.factory.entry_state()
simgr = project.factory.simgr(state)

## Now, let's the binary unpack itself
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x85b853],
                                                        concretize = []))
exploration = simgr.run()
new_concrete_state = exploration.stashes['found'][0]

# Hit the new stub 4 times before having our unpacked code at 0x400cd6
for i in xrange(0,4):
    simgr = project.factory.simgr(new_concrete_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x85b853]))
    exploration = simgr.run()
    new_concrete_state = exploration.stashes['found'][0]

## Reaching the first decision point
simgr = project.factory.simgr(new_concrete_state)
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x400cd6],
                                                        concretize = []))
exploration = simgr.run()
new_concrete_state = exploration.stashes['found'][0]
```

Now the new_concrete_state is synchronized with the program's state at ```0x400cd6```.
To start to explore symbolically the program we should declare as symbolic the portion of memory that hosts the hardcoded configuration used by the malware.
We have identified this previously at the address resolved by the operation ```rbp-0xc0```.

{{< img "Address of the hardcoded configuration" "symbion_ex3.png" >}}

Let's leverage this info to declare such portion of memory symbolic!

```python
# Declaring a symbolic buffer
arg0 = claripy.BVS('arg0', 8*32)

# The address of the symbolic buffer would be the one of the
# hardcoded malware configuration
symbolic_buffer_address = new_concrete_state.regs.rbp-0xc0

# Setting the symbolic buffer in memory!
new_concrete_state.memory.store(symbolic_buffer_address, arg0)
```

Time for some symbolic execution to find the value of the configuration to trigger the dropper behavior of this toy sample. ( for the sake of clarity let's use tag instead of raw addresses )
Also, we are going to instruct angr to specifically avoid, during the symbolic exploration, part of the binary that are related to evasion or behaviors that not interesting for this analysis.

```python
simgr = p.factory.simgr(new_concrete_state)

print("[2]Symbolically executing binary to find dropping of second stage" +
       "[ address:  " + hex(DROP_STAGE2_V2) + " ]")

# Symbolically explore the malware to find a specific behavior by avoiding
# evasive behaviors
exploration = simgr.explore(find=DROP_STAGE2_V2, avoid=[DROP_STAGE2_V1,
                                                       VENV_DETECTED, FAKE_CC ])
# Get our synchronized state back!
new_symbolic_state = exploration.stashes['found'][0]
```

Last step: now that we hold the value of the configuration to trigger that action in the binary, let's concretize it in the memory of the concrete execution and let's enjoy the triggering of our chosen behavior!

```python
print("[3]Executing binary concretely with solution found until the end " +
hex(BINARY_EXECUTION_END))

simgr = project.factory.simgr(new_symbolic_state)

# Concretizing the solution to reach the interesting behavior in the memory
# of the concrete process and resume until the end of the execution.
simgr.use_technique(angr.exploration_techniques.Symbion(find=[BINARY_EXECUTION_END],
                              concretize = [(symbolic_buffer_address,arg0)]))

exploration = simgr.run()

new_concrete_state = exploration.stashes['found'][0]

```

Here we are making use of the *concretize* attribute of the Symbion exploration technique to overwrite that address in the memory of the concrete process with the value held in ```arg0``` that is the solution found with the symbolic execution. By resuming the concrete process now we should see the program dropping the second stage:

```bash
[+]Parsing malware configuration
[+]Executing stage 2 fake malware V2

```

# Extras
## Timeout the concrete execution
The Symbion *ExplorationTechnique* supports the addition of a timeout to the concrete execution; this come handful in cases where you don't hit one of the expected breakpoints and the program keeps running or if hitting one of the breakpoints take a while and you want to be sure that you didn't miss your shot.
In these cases, after an user defined value for the *timeout*, we stop the concrete execution ( warning: the *ConcreteTarget* implementation must implement the ```stop``` method properly ) and angr returns the synchronized state in the *timeout* stash.

```python

#[...]

# specifying a timeout for the concrete execution ( in seconds )
simgr.use_technique(angr.exploration_techniques.Symbion(find=[BINARY_EXECUTION_END],
                              timeout = 10))

exploration = simgr.run()

new_concrete_timeout_state = exploration.stashes['timeout'][0]

```
At this point by investigating the returned state, users can decide to resume the execution again and wait longer or just aborting the analysis or do whatever they want!

## Restoring SimProcedures
If you've decided to use *SimProcedures* during the declaration of the angr's Project:

```python
# Creation of the project with the new attributes 'concrete_target'
p = angr.Project(binary_x64, concrete_target=avatar_gdb,
                             use_sim_procedures=True)  # <---- Using SimProcedures
```

The *Concrete state plugin* tries to update their addresses in the angr's internal SimProcedures table ( i.e. ```project._sim_procedures``` ) in order to avoid to execute libraries code that can sometimes get the *VEX engine* in troubles ( e.g. [dirty calls](https://github.com/angr/angr/blob/master/angr/engines/vex/dirty.py) not implemented ) or lead to a early state explosion.

# Future Works
The current version of Symbion is a very basic implementation of the interesting concept of mixing concrete and symbolic execution to support analysis of very complex target. We have plenty of exciting ideas to push this project:

1. Support for a **snapshot engine** that empowers user to restore a specific state of the concrete process.
2. Support for a **watchpoint mechanism** to support the stopping of the concrete execution as soon as it touches a symbolic defined portion of memory.
3. Support for other architectures ( yeah, right now just x86 is supported! ).
4. Exciting real world demos! :-)

# Conclusions
The presented example showed how we leverage Symbion to discover the malware configuration that eventually trigger a specific action of interest in the binary. We accomplished that by strategically skipping the initial phase of malware unpacking delegating its execution to the concrete environment, then we synchronized the state of the unpacked program inside angr and by declaring part of memory symbolic and levereging symbolic execution we discover the correct value to avoid the malware evasion and trigger the dropping of the second stage.

The flexibility of the designed interface should open the door to different implementations of *ConcreteTargets* and the building of new tools that will let analysts to combine these concrete and symbolic analyses in new and exciting ways.

We think that this new primitive will let us explore new execution method of very complex target
and give space to new ideas regarding the exploitation of symbolic execution for real world
programs. We are excited to release this to the community, to see how you all will use angr to
push the boundaries of program analysis even further.

Stay tuned for more example and updates about the project!
