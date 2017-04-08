# go-libaudit

[![Build Status](http://img.shields.io/travis/elastic/go-libaudit.svg?style=flat-square)][travis]
[![Go Documentation](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)][godocs]

[travis]: http://travis-ci.org/elastic/go-libaudit
[godocs]: http://godoc.org/github.com/elastic/go-libaudit

go-libaudit is a library for Go (golang) for communicating with the Linux Audit
Framework. The Linux Audit Framework provides system call auditing in the kernel
and logs the events to user-space using netlink sockets. This library
facilitates user-space applications that want to receive audit events.

## Installation and Usage

Package documentation can be found on [GoDoc][godocs].

Installation can be done with a normal `go get`:

```
$ go get github.com/elastic/go-libaudit
```

go-libaudit has two example applications that you can use to try the library.
The first is _audit_ which registers to receive audit events from the kernel
and outputs the data it receives to stdout. The system's `auditd` process
should be stopped first.

```
$ go install github.com/elastic/go-libaudit/cmd/audit
$ sudo $GOPATH/bin/audit -d -format=json
```

The second is _auparse_ which parses the log files from the Linux auditd
process.

```
$ go install github.com/elastic/go-libaudit/cmd/auparse
$ sudo cat /var/log/audit/audit.log | auparse | jq .
{
  "@timestamp": "2017-03-31 22:08:25.96 +0000 UTC",
  "a0": "4",
  "a1": "7f808e0c4408",
  "a2": "10",
  "a3": "0",
  "arch": "x86_64",
  "auid": "4294967295",
  "comm": "ntpd",
  "egid": "38",
  "euid": "38",
  "exe": "/usr/sbin/ntpd",
  "exit": "0",
  "fsgid": "38",
  "fsuid": "38",
  "gid": "38",
  "items": "0",
  "pid": "1106",
  "ppid": "1",
  "raw_msg": "audit(1490998105.960:595907): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f808e0c4408 a2=10 a3=0 items=0 ppid=1 pid=1106 auid=4294967295 uid=38 gid=38 euid=38 suid=38 fsuid=38 egid=38 sgid=38 fsgid=38 tty=(none) ses=4294967295 comm=\"ntpd\" exe=\"/usr/sbin/ntpd\" subj=system_u:system_r:ntpd_t:s0 key=(null)",
  "record_type": "SYSCALL",
  "sequence": "595907",
  "ses": "4294967295",
  "sgid": "38",
  "subj": "system_u:system_r:ntpd_t:s0",
  "success": "yes",
  "suid": "38",
  "syscall": "connect",
  "tty": "(none)",
  "uid": "38"
}
```