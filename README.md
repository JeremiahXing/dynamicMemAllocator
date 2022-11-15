
# ANU COMP 2310 Assignment 1

## test:

./test.py -h
usage: test.py [-h] [-t TEST] [--release] [--log] [-m MALLOC]

options:
-h, --help            show this help message and exit
-t TEST, --test TEST  test name to run
--release             build in release mode
--log                 build with logging
-m MALLOC, --malloc MALLOC
allocator name, default to "mymalloc"



usage: bench.py [-h] [-m MALLOC] [-i INVOCATIONS]

options:
-h, --help            show this help message and exit
-m MALLOC, --malloc MALLOC
allocator name, default to "mymalloc"
-i INVOCATIONS, --invocations INVOCATIONS
number of invocations of the benchmark