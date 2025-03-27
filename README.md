# Dynamic Gobuster

Dynamic Gobuster is an advanced directory enumeration tool that extends Gobuster's capabilities by dynamically extracting and enumerating links from HTML responses while running threaded scans. It automates the process of discovering directories and files in web applications.

## Features

- **Dynamic Enumeration:** Extracts and processes links found in HTML responses.
- **Threaded Scanning:** Utilizes multi-threading for efficient scanning.
- **Status Filtering:** Filters and processes only valid status codes (200, 301, 302, 307, 403).
- **Recursive Crawling:** Automatically discovers new paths by analyzing page content.
- **Leaf Node Detection:** Identifies static file extensions (images, CSS, JavaScript, etc.) to avoid unnecessary requests.
- **Reachability Check:** Ensures discovered paths are accessible before further processing.

## Requirements

- Python 3.x
- Gobuster (`go install github.com/OJ/gobuster/v3@latest`)
- cURL (`sudo apt install curl` or `brew install curl`)

## Installation

```bash
git clone https://github.com/yourusername/dynamic-gobuster.git
cd dynamic-gobuster
pip install -r requirements.txt
```

## Usage

```python dynamic-gobuster.py -d <target_url> -p <wordlist_path> -t <num_threads>```

Arguments:
-d, --domain : Target website URL
-p, --dict : Path to the dictionary file (wordlist)
-t, --threads : Number of concurrent threads (default: 10)

## Example

```python dynamic-gobuster.py -d https://example.com -p wordlist.txt -t 20```
