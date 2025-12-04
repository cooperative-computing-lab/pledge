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
  ├─ PID 2082702 (child) [/software/w/wrf/4.7/WPS/WPS-4.6.0/geogrid.exe]
  ├─ PID 2082763 (child) [/software/w/wrf/4.7/WPS/WPS-4.6.0/metgrid.exe]
  ├─ PID 2082794 (child) [/usr/bin/ln]
  ├─ PID 2082795 (child) [/software/w/wrf/4.7/WRF/WRFV4.7.0/run/real.exe]
  ├─ PID 2082820 (child) [/software/w/wrf/4.7/WRF/WRFV4.7.0/run/wrf.exe]
├─ PID 2082710 (root) [unknown]
├─ PID 2082711 (root) [unknown]
├─ PID 2082767 (root) [unknown]
├─ PID 2082768 (root) [unknown]
├─ PID 2082799 (root) [unknown]
├─ PID 2082800 (root) [unknown]
├─ PID 2082821 (root) [unknown]

Access       <Directory>    Count

#Process ID: 0 (root process)
E </afs/crc.nd.edu/user/c/username/miniconda3> (2 files) [enoent: 4]
EM </afs> (13 files) [enoent: 12, stat: 1]
EM </opt> (65 files) [enoent: 59, stat: 6]
EM </software> (34 files) [enoent: 27, stat: 55]
RM </users> (7 files) [read: 11, stat: 9]
#Searching for: x86-64-v3, x86-64-v2, x86_64, haswell, tls, ln
#Read/Write permission mismatches (requested but not performed):
#/dev/tty

...

```

A process tree describes the hierarchy of the program structure. Below the process tree there is an entry for each process describing the I/O behavior. 

### Enforcer

With the contract generated we may now use it in combination with the enforcer on subsequent executions. 
We first have to set the environment variable:<br>
`export CONTRACT=./contract_name`<br>
We use `LD_PRELOAD`, however, `PLEDGE` temporarily writes an `.so` called `minienforcer.so` and appends its path to the `LD_PRELOAD` environment variable, so the user does not have to set it.<br>
We can run our command with:<br>
`pledge enforce cat sample.c`<br>
The output should be something like this:<br>

```
Enforcer path: /home/user/dummy/cat.sample.c.contract
OPEN: caught open with path [sample.c]
with absolute [/home/user/dummy/sample.c]
ALLOWED: Path [/home/user/dummy/sample.c] with permission [R] is not in violation of the contract.
READING: caught path [/proc/self/fd/3] with link to [/home/user/dummy/sample.c]
ALLOWED: Path [/home/user/dummy/sample.c] with permission [R] is not in violation of the contract.
WRITING: caught path [/proc/self/fd/1] with link to [/dev/pts/0]
WHITELISTED: Path [/dev/pts/0] is whitelisted internally.
READING: caught path [/proc/self/fd/3] with link to [/home/user/dummy/sample.c]
ALLOWED: Path [/home/user/dummy/sample.c] with permission [R] is not in violation of the contract.
```

