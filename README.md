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
  "@timestamp": "2017-03-21 23:12:51.011 +0000 UTC",
  "a0": "15",
  "a1": "7ffd83722200",
  "a2": "6e",
  "a3": "ea60",
  "arch": "x86_64",
  "auid": "4294967295",
  "comm": "master",
  "egid": "0",
  "euid": "0",
  "exe": "/usr/libexec/postfix/master",
  "exit": "0",
  "fsgid": "0",
  "fsuid": "0",
  "gid": "0",
  "items": "1",
  "pid": "1229",
  "ppid": "1",
  "raw_msg": "audit(1490137971.011:50406): arch=c000003e syscall=42 success=yes exit=0 a0=15 a1=7ffd83722200 a2=6e a3=ea60 items=1 ppid=1 pid=1229 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"master\" exe=\"/usr/libexec/postfix/master\" subj=system_u:system_r:postfix_master_t:s0 key=(null)",
  "record_type": "SYSCALL",
  "sequence": "50406",
  "ses": "4294967295",
  "sgid": "0",
  "subj_domain": "postfix_master_t",
  "subj_level": "s0",
  "subj_role": "system_r",
  "subj_user": "system_u",
  "success": "yes",
  "suid": "0",
  "syscall": "connect",
  "tty": "(none)",
  "uid": "0"
}
```