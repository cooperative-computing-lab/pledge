# Pledge

Pledge is a utility for understanding and tuning applications.

## Building

Clone the pledge repository and run `make`

## Usage

Pledge consists of two components, the tracer and the enforcer.

### Tracer

To generate a trace/contract for a program, execute your application within the context of the pledge tracer like so:

```sh
pledge --trace ./a.out
```

It should create a file named `(executable name).contract`, as well as a copy of the strace output named `strace_output.log`

You may also generate a contract for a program using an existing strace output. Some versions of strace may be incompatible. The supported strace version is 6.12. 

`strace -f -y` is the minimum specification required but may generate a very large file.

`strace -f -y --trace=file,read,write,mmap,getdents64,lseek,clone` will record only the necessary information. 

The contract may be generated from the existing strace output like so:

```sh
pledge --trace -f strace_output.log
```

The contract file will look something like the text below. 

```
#Process Tree:
├─ PID 0 (root) [./batch_wrf.sh]
  ├─ PID 2082651 (child) [/software/w/wrf/4.7/WPS/WPS-4.6.0/link_grib.csh]
    ├─ PID 2082652 (child) [unknown]
    ├─ PID 2082653 (child) [/usr/bin/rm]
    ├─ PID 2082654 (child) [/usr/bin/ln]
    ├─ PID 2082655 (child) [/usr/bin/ln]
    ├─ PID 2082656 (child) [/usr/bin/ln]
    ├─ PID 2082657 (child) [/usr/bin/ln]
    ├─ PID 2082658 (child) [/usr/bin/ln]
    ├─ PID 2082659 (child) [/usr/bin/ln]
    ├─ PID 2082660 (child) [/usr/bin/ln]
    ├─ PID 2082661 (child) [/usr/bin/ln]
    ├─ PID 2082662 (child) [/usr/bin/ln]
  ├─ PID 2082664 (child) [/software/w/wrf/4.7/WPS/WPS-4.6.0/ungrib.exe]
      Read Files: x, y, z
      Write Files: a, b, c
      Executable: ungrib.exe x y z a b c
  ├─ PID 2082702 (child) [/software/w/wrf/4.7/WPS/WPS-4.6.0/geogrid.exe]
  ├─ PID 2082763 (child) [/software/w/wrf/4.7/WPS/WPS-4.6.0/metgrid.exe]
  ├─ PID 2082794 (child) [/usr/bin/ln]
  ├─ PID 2082795 (child) [/software/w/wrf/4.7/WRF/WRFV4.7.0/run/real.exe]
  ├─ PID 2082820 (child) [/software/w/wrf/4.7/WRF/WRFV4.7.0/run/wrf.exe]

```

A process tree describes the hierarchy of the program structure. Below each process there are entries describing the I/O behavior. 

### Contract Utility - Workflow Generation

The contract can be viewed as-is to understand the behavior of the application. It offers the user a way to see all of the files that were
interacted with, including those implicitly referred to by the executables that would have not been identified by simply reading the application. 

The contract may also be parsed further, by `parse_contract.py`, which will create a Makefile-based DAG of the application. This representation can be understood by Makeflow, a CCTools workflow description language. Subsequently Makeflow can execute the application using a variety of executors such as TaskVine or WorkQueue. It also provides functionality to deploy workers on a variety of batch systems like Slurm and HTCondor. 