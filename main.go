package main

import (
	"bytes"
	"code.google.com/p/go.exp/inotify"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sync"
)

var (
	cpus    = flag.Int("cpus", 2, "number of active OS threads")
	watcher *inotify.Watcher
	rules   *Rules
)

const (
	ruleUrl string = "https://www.rfxn.com/api/?id=all"
)

func watchDir(path string) {
	lfi, err := os.Lstat(path)
	if err != nil {
		log.Printf("%v", err)
		return
	}

	if lfi.IsDir() {
		log.Println("Adding directory to watch ", path)
		if err := watcher.AddWatch(path, inotify.IN_MODIFY|inotify.IN_CREATE|inotify.IN_MOVED_TO); err != nil {
			log.Println("Error while adding new directory to watch: ", err)
		}

		dir, err := ioutil.ReadDir(path)
		if err != nil {
			log.Printf("%v", err)
			return
		}

		for _, v := range dir {
			watchDir(path + "/" + v.Name())
		}
		return
	}
}

func scanner(scan chan string) {
	for path := range scan {
		log.Println("I'm starting the scan of ", path)

		// check file size
		fi, err := os.Stat(path)
		if err != nil {
			log.Printf("%v", err)
			break
		}
		size := fi.Size()
		log.Println("File size is ", size)

		if size > 10*1024*1024*1024 {
			break
		}

		// calculate MD5 sum
		data, err := ioutil.ReadFile(path)
		if err != nil {
			break
		}
		sum := fmt.Sprintf("%x", md5.Sum(data))
		log.Println("File MD5 sum is ", sum)

		// search for MD5 hash
		rules.m.RLock()
		for _, sig := range rules.Signatures {
			if sig.Format == "MD5" && sig.Sig == sum {
				log.Printf("Detected a threat in %s by MD5 rule %s from %s", path, sig.Name, sig.Time)
				break
			} else if sig.Format == "HEX" {
				bytesig, err := hex.DecodeString(sig.Sig)
				if err != nil {
					log.Printf("Cannot decode HEX rule %s", sig.Sig)
					break
				}
				if bytes.Contains(data, bytesig) {
					log.Printf("Detected a threat in %s by HEX rule %s from %s", path, sig.Name, sig.Time)
					break
				}
			}
		}
		rules.m.RUnlock()
		log.Println("I just finished scanning ", path)
	}
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("error: missing path")
	}

	runtime.GOMAXPROCS(*cpus)

	var err error
	watcher, err = inotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	rules = &Rules{
		m: new(sync.RWMutex),
	}
	loadRules(rules)

	scan := make(chan string)

	for i := 0; i < *cpus; i++ {
		go scanner(scan)
	}

	for _, v := range args {
		watchDir(v)
	}
	log.Println("Watcher preload done. Scanner ready.")

	for {
		select {
		case ev := <-watcher.Event:
			log.Println("event: ", ev)
			if ev.Mask&inotify.IN_ISDIR == 0 {
				scan <- ev.Name
			}
			/* If a directory is created and files are created in it before a watcher
			 * is set up to monitor the directory, they are not scanned.
			 */
			if ev.Mask&inotify.IN_CREATE != 0 && ev.Mask&inotify.IN_ISDIR != 0 {
				log.Println("directory has been created, watching it too")
				watchDir(ev.Name)
			}
		case err := <-watcher.Error:
			log.Println("error: ", err)
		}
	}
}
