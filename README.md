gonotifyav
============
* it is an AntiVirus scanner to detect common webhosting threats
* it uses wonderful rules provided by [R-fx Networks](https://www.rfxn.com/) at https://www.rfxn.com/api/?id=all
* it supports MD5 sum and HEX-style rules from ClamAV
* it is a fast replacement for [LMD (meldet a.k.a. maldetect)](https://www.rfxn.com/projects/linux-malware-detect/)
* it always downloads fresh rules on start-up (a feature not bug)
* it uses ```inotify``` in Linux kernel to monitor given directories for ```IN_MODIFY```, ```IN_CREATE``` and ```IN_MOVED_TO```
events
* it scans all detected files smaller than 10 MB and recursively adds new children directories to watch

How to build
============
```bash
aptitude install mercurial
go get code.google.com/p/go.exp/inotify
go get code.google.com/p/go-charset/charset
go build
```

How to use
============
```-cpu``` flag is optional and allows to set the number of OS threads used for multi-threading (default: 2)

At least one argument is required, specify paths to directories to watch.

```bash
./gonotifyav /home /tmp
```
