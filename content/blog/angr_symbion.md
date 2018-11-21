---
title: "symbion: fusing concrete and symbolic execution"
date: 2018-11-20T15:48:59-08:00
draft: false
authors: ["degrigis", "subwire"]
tags: ["announcements", "symbion"]
preview: "Learn how to perform symbolic execution on real-world binaries by fusing concrete and symbolic execution"
---

Today we are going to talk about an exciting new feature that we have recently released on angr's master: Symbion, a brand new exploration technique aimed to overcome some of the complexities that real-world programs exhibit and that can't or are not currently modeled in our symbolic engine.

# Motivation

When we leverage a symbolic execution tool such as angr to analyze a program, we depend on a model of the operating system and libraries to make the analysis tractable ( in fact trying to symbolically execute everything would lead immediately to a state explosion).
However, there are a lot of libraries and system calls out there, and we cannot hope to model them all.  In the case that a program requires an unmodeled procedure, we generally either lose precision, encounter state explosion or spend a lot of time developing a SimProcedure. For real-world programs, this can become a huge barrier to a useful analysis.

**Instead of modeling, Symbion levereges a concrete execution of a program to support the symbolic analysis**.

Analysts may wish to symbolically reason about control flow of a program between two program points B and C, but can't even execute from point A to point B due to unmodeled behaviors. With Symbion, they can execute concretely up to point B, switch into angr's symbolic context, and compute the program input needed to reach point C.  The solution obtained by angr can then be written into the program's memory and by resuming the concrete execution reaching beyond point C.

{{< img "symbion working" "symbion_working.jpg" >}}

In academia, previous works have explored similar ideas with projects like [Mayhem](https://users.ece.cmu.edu/~dbrumley/pdf/Cha%20et%20al._2012_Unleashing%20Mayhem%20on%20Binary%20Code.pdf), [AVATAR](http://s3.eurecom.fr/docs/bar18_muench.pdf) and [S2E](https://cseweb.ucsd.edu/~dstefan/cse291-fall16/papers/s2e.pdf). We leverege some of the interesting ideas implemented in these projects with the aim of making a hybrid concrete/symbolic approach that is easy to use and flexible enough to build upon.

Our main design goals are:

1. Couple the concrete environment to the symbolic environment, without depending on what the concrete environment is and letting users to implement new "concrete target" ( the object responsible to control the concrete execution of the program in the concrete environment ) through a well-defined and simple interface.

2. Allow context switches between concrete and symbolic (and vice versa), without expensive transfers of state.

3. Allow changes to the concrete state, to enable further exploration based on the results of angr analyses.

With these goals in mind, we have worked to create Symbion, while minimizing the changes to the overall angr environment and workflow.

# System overview

{{< img "symbion system overview" "system_overview_symbion.png" >}}

The first thing we need to do when performing an analysis is creating the concrete environment we wish to use.  Symbion adds the notion of a ConcreteTarget, a generic abstraction for any execution environment that defines simple memory, register, and execution control interactions.

For example, to connect to GDB:

```python
from angr_targets import AvatarGDBConcreteTarget

# Start a GDB
subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,'/bin/ls'),
                  stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE, shell=True)

# Instantiation of the AvatarGDBConcreteTarget
avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP,
                                    GDB_SERVER_PORT)
```

While here we use a GDB concrete target, it is totally possible to implement new targets ( like full-system emulators, hardware via an attached debugger, a Windows debugger,... ) by implementing a very simple interface:

```python
   def read_memory(self, address, length, **kwargs):
   def write_memory(self, address, data, **kwargs):
   def read_register(self, register, **kwargs):
   def write_register(self, register, value, **kwargs):
   def set_breakpoint(self, address, **kwargs):
   def remove_breakpoint(self, address, **kwargs):
   def get_mappings(self):
   def run(self):
```

The attentive reader may notice that this API bears a striking similarity to the [interface]() used by the AVATAR target-orchestration framework; this is intentional, and we inherit target code and capabilities from Avatar's collection of pluggable targets.

Next, we need to create the angr environment.  This is done in the usual way, but specifying that a concrete target is to be used:

```python

p = angr.Project(binary_x64, concrete_target=avatar_gdb,
                 use_sim_procedures=True)
```

The primary user-facing component of Symbion is its Symbion ExplorationTechnique, which works similarly to the other available techniques. This allows us to execute the program until a certain address is reached, or any number of other conditions.

Translating this idea into the script, let's say we want to reach 0x4007a4:

```python
# Create the state at the beginning of the program
entry_state = p.factory.entry_state()
# Create a simulation manager to hold this exploration
simgr = p.factory.simgr(entry_state)
# Explore the program concretely until we reach 0x4007a4
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x4007A4]))
exploration = simgr.run()
```

While this seems simple, a lot of the complexity of Symbion is hidden in the transition between the concrete and the symbolic contexts. The whole magic occurs through a new angr execution engine (SimEngineConcrete) and an accompanying state plugin ( these are complex enough to warrant their own blog post and will be discussed later ).
For now, it suffices to say that at the end of its execution (when we have reached the target address), the SimConcreteEngine returns a SimState reflecting the current state of the concrete target.

{{< img "symbion flow" "symbion.gif" >}}

However, this synchronization does _not_ need to copy any memory; during the synchronization with the concrete target, we modify the state's memory backend such that reads are lazily redirected to the underlying concrete memory.

{{< img "symbion memory redirection" "memory_redirection.jpg" >}}

We are again free to perform any analysis we wish.  Note that while this state forwards memory reads to the underlying concrete target, writes are _not_ forwarded, and will remain only in this symbolic state, until they are concretized and applied to the target.
Concretization is triggered by the use of the `concretize` argument passed to Symbion. We only need to supply a list of addresses, and the variable we wish to solve for.

```python
simgr.use_technique(angr.exploration_techniques.Symbion(find=[BINARY_EXECUTION_END],
                                  concretize = [(address,my_variable)]))
```

# Example

For this example, we are going to use a homemade toy binary (a 64-bit Linux ELF) that will make decisions about the execution based on an internal hardcoded configuration.
The binary has also been packed with UPX in order to hinder as much as possible the analysis with angr.

Disclaimer: this homemade "malware" is definitely not a real-world case scenario, but its level of complexity is perfectly suited for showing how Symbion works. We are planning to show you real-world cases in future blog posts!

Let's begin!

First thing first, let's get familiar with our binary.
You can get a [copy](https://github.com/angr/binaries.git in tests/x86_64/packed_elf64) from the angr `binaries` repository

By executing it, you have a surprise:

```
[+] Parsing malware configuration
[+] Virtual environment detected!
```

Seems that we have an evasive behavior here!
We leave the reversing of the binary and the discovering of its original entry point (OEP) as an exercise to the reader, but for the sake of our example, we'll spoil it: 0x400b95.
We then execute the binary until we reach the OEP, using the procedure outlined above, and construct the control-flow graph of the unpacked binary.
By looking at the CFG at the OEP we can easily see 4 possible behaviors of the binary:

{{< img "cfg packed 64" "screenshot_cfg_packed64.png" >}}

All this behavior depends on the hardcoded configuration mentioned at the beginning. We can spot the usage of this configuration at the address 0x400cd6: the point where the first decision is taken from the binary.
Seems that with the default hardcoded configuration we are following the yellow path!

{{< img "default config packed64" "default_config_packed64.png" >}}

Now, as analysts, our job here is to study this binary's malicious behavior, and how it is triggered.  We see some nasty secondary payload dropped starting in the basic block at 0x400d6a; how do we get there? And what about the basic block 0x400d99? Well, this is what symbolic execution is good for!

The idea is to let the binary unpack itself and reach concretely the position where the first decision is taken ( the address 0x400cd6 ), synchronize the state inside angr, define as symbolic the configuration buffer, explore symbolically and resume the program as we whish given the solution provided by angr!

However, this binary is packed, and the memory there will be overwritten by the unpacking process.  Software breakpoints, like the ones used by GDB, will be overwritten as well.
Instead, we manually reverse-engineer the binary and determine that we can execute from the beginning of the program until 0x85b853 to have a new stub available at 0x45b97f and eventually wait for 4 breakpoint hits to this address to have our unpacked code at 0x400cd6.

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

## Now, unpack the binary

simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x85b853],
                                                        concretize = []))
exploration = simgr.run()
new_concrete_state = exploration.stashes['found'][0]

# hit the new stub 4 times before having our unpacked code at 0x400cd6
for i in xrange(0,4):
    simgr = project.factory.simgr(new_concrete_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x85b853]))
    exploration = simgr.run()
    new_concrete_state = exploration.stashes['found'][0]

## Now, reach the first decision point

simgr = project.factory.simgr(new_concrete_state)
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x400cd6],
                                                        concretize = []))
exploration = simgr.run()
new_concrete_state = exploration.stashes['found'][0]
```

Now the new_concrete_state is synchronized with the program's state at 0x400cd6.
To start to explore symbolically the program we should declare as symbolic the portion of memory that hosts the hardcoded configuration used by the malware.
We have identified this previously at the address resolved by the operation rbp-0xc0.

{{< img "" "rbp_screenshot.png" >}}

Let's leverage this info to declare such portion of memory symbolic!

```python
arg0 = claripy.BVS('arg0', 8*32)
symbolic_buffer_address = new_concrete_state.regs.rbp-0xc0
new_concrete_state.memory.store(symbolic_buffer_address, arg0)
```

Time for some symbolic execution to find the value of the configuration to trigger the dropper behavior of this toy sample. ( for the sake of clarity let's use tag instead of raw addresses )
Also, we are going to instruct angr to specifically avoid, during the symbolic exploration, part of the binary that are related to evasion or behaviors that not interesting for this analysis.

```python
simgr = p.factory.simgr(new_concrete_state)

print("[2]Symbolically executing binary to find dropping of second stage +
       "[ address:  " + hex(DROP_STAGE2_V2) + " ]")

exploration = simgr.explore(find=DROP_STAGE2_V2, avoid=[DROP_STAGE2_V1,
                                                       VENV_DETECTED, FAKE_CC ])
new_symbolic_state = exploration.stashes['found'][0]
```

Last step: now that we hold the value of the configuration to trigger that action in the binary, let's concretize it in the memory of the concrete execution and let's enjoy the triggering of our chosen behavior!

```python
print("[3]Executing binary concretely with solution found until the end " +
hex(BINARY_EXECUTION_END))

simgr = project.factory.simgr(new_symbolic_state)
simgr.use_technique(angr.exploration_techniques.Symbion(find=[BINARY_EXECUTION_END],
                              concretize = [(symbolic_buffer_address,arg0)]))
exploration = simgr.run()
new_concrete_state = exploration.stashes['found'][0]

```

Here we are making use of the *concretize* attribute of the Symbion exploration technique to overwrite that address in the memory of the concrete process with the value held in arg0 that is the solution found with the symbolic execution. By resuming the concrete process now we should see the program dropping the second stage:

```
[+] Parsing malware configuration
[+] Executing stage 2 fake malware V2
```

# Conclusions
The presented example showed how we leverage Symbion to discover the malware configuration that eventually trigger a specific action of interest in the binary. We accomplished that by strategically skipping the initial phase of malware unpacking delegating its execution to the concrete environment, then we synchronized the state of the unpacked program inside angr and by declaring part of memory symbolic and levereging symbolic execution we discover the correct value to avoid the malware evasion and trigger the dropping of the second stage.   

The flexibility of the designed interface should open the door to different implementations of ConcreteTargets and the building of new tools that will let analysts to combine these concrete and symbolic analyses in new and exciting ways.

We think that this new primitive will let us explore new execution method of very complex target
and give space to new ideas regarding the exploitation of symbolic execution for real world
programs. We are excited to release this to the community, to see how you all will use angr to
push the boundaries of program analysis even further.
Stay tuned for more example and updates about the project!

