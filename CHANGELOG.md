# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

## [0.0.2]

### Added
- Added `libaudit.Reassembler` for reassembling out of order or interleaved
  messages and providing notification for lost events based on gaps in sequence
  numbers. a60bdd3b1b642cc80a3872d999114ae675456768
- auparse - Combine EXECVE arguments into a single field called `cmdline`.
  468a9eb0898e0efd3c2fd7abf067519cb63fa6c3
- auparse - Split SELinux subjects into `subj_user`, `subj_role`,
  `subj_domain`, `subj_level`, and `subj_category`.
  f3ed884a7c03ea75c9ec247251905aa1ec548959
- auparse - Replace auid values `4294967295` and `-1` with `unset` to convey
  the meaning of these values. #5
- aucoalesce - Added a new package to coalescing related messages into a single
  event. #1

### Changed
- auparse - Changed the behavior of `ParseLogLine()` and `Parse()` to only parse
  the message header. To parse the message body, call `Data()` on the returned
  `AuditMessage`.

### Deprecated

### Removed

## [0.0.1]

### Added
- Added AuditClient for communicating with the Linux Audit Framework in the
  Linux kernel.
- Added auparse package for parsing audit logs.
