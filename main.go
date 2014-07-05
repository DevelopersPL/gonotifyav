package main

import (
	"bytes"
	"code.google.com/p/go.exp/inotify"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"sync"
	"syscall"
)

var (
	cpus      = flag.Int("cpus", 2, "number of active OS threads")
	delete    = flag.Bool("delete", false, "delete detected threats")
	maxsize   = flag.Int("maxsize", 10, "maximum size in MB of size to be scanned")
	notifyurl = flag.String("notify", "", "the URL to send a POST notifiction with JSON-encoded info about a threat")
	watcher   *inotify.Watcher
	rules     *Rules
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

func action(path string) {
	if *delete {
		if err := os.Remove(path); err != nil {
			log.Printf("Could not delete file %s", path)
		} else {
			log.Printf("Deleted file %s", path)
		}
	}
}

type notification struct {
	Path   string
	Threat string
	Owner  string
}

func notify(path, threat, owner string) {
	if *notifyurl != "" {
		tmp := notification{Path: path,
			Threat: threat,
			Owner:  owner,
		}
		body, err := json.Marshal(&tmp)
		log.Println(string(body))
		if err != nil {
			log.Printf("Error encoding JSON notification: %s", err)
			return
		}
		buf := bytes.NewBuffer(body)
		if _, err := http.Post(*notifyurl, "application/json", buf); err != nil {
			log.Printf("Error sending notification to %s", notify)
		}
	}
}

func scanner(scan chan string) {
	for path := range scan {
		log.Println("Starting the scan of ", path)

		// check file size
		fi, err := os.Stat(path)
		if err != nil {
			log.Printf("%v", err)
			break
		}
		size := fi.Size()
		log.Println("File size is ", size)

		if size > int64((*maxsize)*1024*1024*1024) {
			break
		}

		// look up owner's username
		uid := fmt.Sprintf("%v", fi.Sys().(*syscall.Stat_t).Uid)
		var owner string
		if u, err := user.LookupId(uid); err != nil {
			owner = uid
		} else {
			owner = u.Username
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
		threat := ""
		for _, sig := range rules.Signatures {
			if sig.Format == "MD5" && sig.Sig == sum {
				log.Printf("Detected a threat in %s by MD5 rule %s from %s", path, sig.Name, sig.Time)
				threat = sig.Name
				break
			} else if sig.Format == "HEX" {
				bytesig, err := hex.DecodeString(sig.Sig)
				if err != nil {
					log.Printf("Cannot decode HEX rule %s", sig.Sig)
					break
				}
				if bytes.Contains(data, bytesig) {
					log.Printf("Detected a threat in %s by HEX rule %s from %s", path, sig.Name, sig.Time)
					threat = sig.Name
					break
				}
			}
		}
		rules.m.RUnlock()
		if threat != "" {
			action(path)
			notify(path, threat, owner)
		}
		log.Println("Finished scanning ", path)
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
