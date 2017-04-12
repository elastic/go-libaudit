# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

### Added
- auparse - Combine EXECVE arguments into a single field called `cmdline`.
- auparse - Split SELinux `subj` field into `subj_user`, `subj_role`,
  `subj_domain`, `subj_level`, and `subj_category`.

### Changed

### Deprecated

### Removed

## [0.0.1]

### Added
- Added AuditClient for communicating with the Linux Audit Framework in the
  Linux kernel.
- Added auparse package for parsing audit logs.
