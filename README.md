Copyright (c) 2019, Johns Hopkins University Applied Physics Laboratory
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Tracer
======

Tracer aims to be a simple utility for tracing process fork()/exec()
calls. Its primary intended use is for tracing project build processes
to enable static analysis tools. `tracer` runs a command and produces a
JSON-like [1] output file describing all sub-commands including their initial
environment, working directory, and arguments.

Tracer may be useful for a variety of tasks, but it was created for
monitoring build processes and reproducing builds.  For example, if you
built a project but want to know how an individual file was compiled or
linked, rebuild using tracer.  The output of tracer will include an
entry for every invocation of the compiler or linker, including all
arguments and environment details.

Building
========

Tracer requires gcc to build; any version which supports the GNU-99 C
standard should be fine.  Currently, tracer only works on x86_64 systems.

Build with make:

```
$ make
```

This will build `tracer`. Install by adding `tracer` to your PATH, for example:

```
$ export PATH=$PATH:$PWD
```

or

```
$ sudo cp tracer /usr/bin
```

Usage
=====

```
tracer [--no-record-env|-E] [--verbose|-v] [--log|-l <file>]
       [--dont-descend|-d cmd] [--dont-descend-re|-D regex] [--tracee-error-code|-c NUM]
       [--child-out|-o <file>] [--child-error|-e <file>] [--stream-execs-mode|-s]
       <tracefile> -- <prog> [args...]
```

`prog` is the program you wish to trace.  It, and its descendants, will be traced and
data about their run will be written to `tracefile`.

Usage Example
===========

Say you have a project which is built using `make` in the current directory.  You wish to
trace the build targets for `foo`, `bar`, and `baz`.  Information about the build process
will be written to `proc.json`:

```
$ tracer proc.json -- make foo bar baz
```

Additional Options
==================

Options to `tracer` must be specified before the `--` token.

  * `--no-record-env` or `-E`: Do not save the state of the environment to file.
  * `--verbose` or `-v`: Display verbose debugging information about tracer to a logfile.
  * `--log <file>` or `-l <file>`: Required if `--verbose` or `-v` is used. The logfile
  for tracer.
  * `--dont-descend <cmd>` or `-d <cmd>`: Ignore children of processes with name `<cmd>`.
  May be provided multiple times.
  * `--dont-descend-re <regex>` or `-D <regex>`: Ignore children of processes whose name
  matches POSIX regex `<regex>` (not PCRE).  May be provided multiple times.
  * `--tracee-error-code <NUM>` or `-c <NUM>`: If enabled, in the event that the initial
  tracee returns an exit code, `tracer` will return `NUM`.  Otherwise, `tracer` will
  return 0 (success) unless `tracer` itself encounters an error.
  * `--child-out <file>` or `-o <file>`: Run the top-level tracee with stdout redirected to
  `file`.  This will be inherited by tracee's children.
  * `--child-error <file>` or `-e <file>`: Run the top-level tracee with stderr redirected
  to `file`.  This will be inherited by tracee's children.
  * `--stream-execs-mode` or `-s`: Do not wait for tracee and its children to complete
  before writing output to the JSON file.  Write to file continuously as soon as new
  information is available. Normally, `tracer` will track the parentage of processes
  and output them as a hierarchical tree; if this option is specified, all processes
  will be given a top-level JSON entry, and parentage will be ignored.

Limitations
===========

Tracer assumes that a process `exec()`s at most once. If a process
`exec()`s multiple times, only the final program image (env, cwd,
argv) is recorded in tracers output. This is a faulty assumption but
works well enough for our needs because the various compilers we care
about don't re-`exec()` once invoked.

The `ptrace()` API is kind of brain dead and seems to cause deadlock
conditions on older kernels.


Tracing Java Build Processes
============================

Tracer only works if the traced process actually uses `exec()`. Certain Java
build systems will perform compilation internally by default.  This section
describes how to modify Gradle, Ant, and Maven projects to call `javac` in
a separate process, making compilation visible to `tracer`.

Gradle
------

Set the environment variable GRADLE_OPTS:
```
$ export GRADLE_OPTS=-Dorg.gradle.daemon=false
```

And add the following to `build.gradle`:

```
allprojects {
    tasks.withType(JavaCompile) {
        options.fork = true
        options.forkOptions.executable = 'javac'
    }
}
```

Ant
---

Add the attribute `fork="true"` to all `<javac>` nodes in the Ant build files.

Maven
-----

Add `-Dmaven.compiler.fork=true` to the command line.


Footnotes
=========

[1]: tracer output will be a valid JSON file in the common case in which all environment,
argument, and working directory contents are valid UTF-8.  Because POSIX allows non-UTF-8
data but the JSON specification does not, tracer output may contain non-UTF-8 data, and
is not fully compliant.
