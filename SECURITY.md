# Security

rathunter is a read-only scanner: it runs local system commands such as `codesign`, `ps` and `netstat`, and it reads files. It never writes outside the report file you ask for, and it makes no network requests.

**Found a vulnerability in rathunter itself** (for example, a file on disk that makes the scanner execute code)? Please report it privately through [GitHub's private vulnerability reporting](https://github.com/annapurnageeks/rathunter/security/advisories/new) instead of opening a public issue.

**Found spyware that rathunter missed, or a false alarm?** Open a regular issue. Describe the persistence method or behaviour, and remove personal data. Please don't attach live malware samples. Share hashes or a link to a public analysis (VirusTotal, Objective-See, etc.) instead.
