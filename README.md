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
Optional flags:
* ```--cpu 2``` (default: 2) set the number of OS threads used for multi-threading
* ```--delete 1``` (default: false) delete detected threats
* ```--maxsize 10``` (default: 10) skip files bigger than given number of MB
* ```--notify http://localhost/path``` (default: none) send an HTTP POST notification about each detected threat
* ```--quarantine /var/quarantine``` (default: none) move threats to this directory

You can only choose one of ```delete``` or ```quarantine```. Deletion takes precedence.

At least one positional argument is required, specify paths to directories to watch.

```bash
./gonotifyav /home /tmp /dev/shm
```

Notification body format
============
```json
{"Path":"/tmp/c99.txt","Threat":"web.malware.unclassed.155","Owner":"root"}
```

Quarantine
============
* Quarantine directory will be created if it doesn't exist.
* Files will be moved into subdirectories with the name of Unix timestamp
* Files moved there will not have their permissions altered so make sure that regular users don't have access to it.
