# PHP Webshell POST Brute-Force Tool

A Python-based multi-threaded PHP Webshell POST brute-force tool, featuring **20-thread concurrent brute-forcing**, **phpinfo() execution verification**, **real-time progress bar**. It resolves common issues with traditional brute-force tools such as frozen progress bars and inability to interrupt.

## Core Features

- 🚀 **Multi-threaded Concurrency**: Up to 20 threads, automatically adapts to password quantity, and supports thread status monitoring
- ✅ **Accurate Validation**: Executes `phpinfo();` via POST and matches page features to avoid false positives
- 📊 **Real-time Progress**: Independent progress refresh thread, displaying brute-force progress (percentage/attempted count) in real time
- 🛡️ **Exception Handling**: Captures request timeouts and connection exceptions to prevent thread blocking

## Environment Requirements

### Python Version

Python 3.7+ (Python 3.8-3.11 recommended, compatible with major operating systems)

### Dependency Libraries

Only relies on `requests` and `urllib3` (Python built-in libraries do not require additional installation). See `requirements.txt` for details:

```txt

requests>=2.31.0
urllib3>=2.0.7
```

## Installation Steps

1. Clone or download the tool to your local machine

2. Install dependencies:
        `pip install -r requirements.txt
# Add --user flag if permission is insufficient
pip install --user -r requirements.txt`

## Usage Instructions

### 1. Prepare Dictionary Files

The tool reads 3 dictionary files in the current directory by default; custom paths are supported:

|Filename|Purpose|Format Example|
|---|---|---|
|`urls.txt`|List of target base URLs|`http://127.0.0.1:15999/`|
|`shell.txt`|List of Webshell paths|`shell.php`, `dama.php`|
|`pass.txt`|Brute-force password dictionary|`123456`, `admin`, `password`|
|**Format Requirement**: One entry per line, automatic deduplication/empty line removal, encoded in UTF-8.|||

### 2. Run the Tool

Execute the script directly:

```bash

python webshell_brute.py
```

### 3. Interaction Flow

1. After startup, the script prompts for dictionary paths (press Enter to use default paths);

2. Loads dictionaries and displays the number of entries after deduplication;

3. Bulk detects the survival status of target URLs + Shell paths;

4. Starts multi-threaded brute-forcing for surviving PHP Webshells;

5. Displays a real-time progress bar during brute-forcing; press `Ctrl+C` to interrupt at any time;

6. Immediately outputs the correct password, response status code, and other information when brute-forcing succeeds.

## Core Configuration Instructions

Core parameters can be adjusted at the top of the script:

|Parameter Name|Default Value|Description|
|---|---|---|
|`TIMEOUT`|3|Request timeout in seconds (shorter values reduce thread blocking)|
|`MAX_THREADS`|20|Maximum number of concurrent threads|
|`PROGRESS_REFRESH_INTERVAL`|0.1|Progress bar refresh interval in seconds|
|`RETRY_TIMES`|0|Number of request retries (recommended to keep 0 to avoid blocking)|
## Output Example

```bash

===== PHP Webshell Multi-threaded POST Brute-force Tool (Supports Ctrl+C Exit) =====

Core Configuration: Threads=20 | Request Timeout=3s

URL list path (default: ./urls.txt):
Webshell path dictionary (default: ./shell.txt):
Password dictionary path (default: ./pass.txt):

[Loading Dictionaries] --------------------------
[Dictionary Loaded] ./urls.txt → Original:1 | Deduplicated:1
[Dictionary Loaded] ./shell.txt → Original:2 | Deduplicated:2
[Dictionary Loaded] ./pass.txt → Original:10002 | Deduplicated:9876

[Scanning Targets] --------------------------

[Detecting Target] http://127.0.0.1:15999/
[Not Alive] http://127.0.0.1:15999/dama.php (HTTP 404)
[Alive] http://127.0.0.1:15999/shell.php → Starting brute-force

[Brute-force Started] Target: http://127.0.0.1:15999/shell.php | Password Count:9876 | Threads:20
[Thread Started] ID:1 → Remaining in Queue:9876
[Thread Started] ID:2 → Remaining in Queue:9875
...
[Brute-force Progress] |████████████------------------------| 25.0% (2469/9876) | Target: shell.php

[✅ Brute-force Succeeded] Thread 5 | Password: 123456
[Response] HTTP 200 | Length: 8965 Bytes

[Thread Exited] ID:1 → Global Exit Flag: False
...
[Scanning Completed] All targets processed
```

## Frequently Asked Questions (FAQ)

### Q1: Progress bar freezes and doesn't update?

- Cause: Single request blocking/thread suspension;

- Solution: Shorten `TIMEOUT` (e.g., set to 3 seconds) and disable retries (`RETRY_TIMES=0`).

### Q2: Cannot exit with Ctrl+C?

- The tool has built-in signal capture mechanism. If exit still fails, wait 0.5 seconds (signal processing delay) or close the terminal directly.

### Q3: Brute-force succeeds but the Webshell is unavailable?

- The verification logic matches `phpinfo()` page features. If the Webshell restricts `phpinfo();` execution, modify the verification rule (adjust the `PHPINFO_PATTERN` regex).

## Notes

1. **Legal Usage**: Only for authorized penetration testing scenarios; unauthorized attacks are prohibited.

2. **Network Environment**: Ensure the target is network-reachable to avoid connection exceptions caused by firewalls/proxies.

3. **Performance Control**: Adjust the number of threads according to the target server's performance to prevent downtime due to excessive concurrency.

4. **Encoding Compatibility**: Dictionary files are recommended to use UTF-8 encoding to avoid garbled Chinese passwords.

## Disclaimer

This tool is for security research and authorized testing only. Users must comply with relevant laws and regulations such as the *Cybersecurity Law*. All legal liabilities arising from improper use of the tool shall be borne solely by the user.

> （注：文档部分内容可能由 AI 生成）