# Bluetooth Fuzzer

Generic bluetooth dumb fuzzer. Low effort, was not tested much, but I can tell you that 60% of the time it works every time.

## Build

install bluetooth library files (`extra/bluez-libs`)

`gcc bt-fuzzer.c -o bt-fuzzer -lbluetooth`

## Usage

```
$ ./bt-fuzzer 
Usage: bt-fuzzer [options] -p <prototype> -b <XX:XX:XX:XX:XX:XX>
  -h	Print this help and exit
  -s  	Provide a fixed seed to reproduce a test case
  -i  	Number of iterations to fuzz 
  -p  	Prototype socket to fuzz (l2cap, rfcomm, avdtp, sco)
  -c  	Channel (Required if rfcomm protocol)
  -v  	Verbose
  -b  	Bluetooth Device Hardware ID to fuzz (XX:XX:XX:XX:XX:XX)
```

Requires root privileges for RAW socket usage.