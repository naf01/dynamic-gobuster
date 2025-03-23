import os
import subprocess
import queue
import re
import threading
import argparse
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor

def split_path(path):
    parts = path.strip("/").split("/")
    hierarchy = set()
    for i in range(len(parts)):
        hierarchy.add("/" + "/".join(parts[:i + 1]))
    return hierarchy

def gobuster_scan(domain, dict_path):
    cmd = ["gobuster", "dir", "-u", domain, "-w", dict_path, "-t", str(thread_count), "-q"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    directories = set()
    valid_status_codes = {"200", "301", "302", "307", "403"}

    print(f"[*] Running Gobuster scan on {domain}...")
    for line in iter(process.stdout.readline, ''):
        match = re.search(r"(/\S+)\s+\(Status:\s*(\d{3})\)", line.strip())
        if match:
            dir_path, status_code = match.groups()
            if status_code in valid_status_codes:
                directories.update(split_path(dir_path))
                print(f"[+] Found: {dir_path} (Status: {status_code})")

    process.stdout.close()
    process.wait()
    return sorted(directories)

def extract_links(html_content, base_url):
    links = set()
    for match in re.findall(r'href=["\'](.*?)["\']', html_content):
        full_url = urljoin(base_url, match)
        parsed_url = urlparse(full_url)
        if parsed_url.netloc == urlparse(base_url).netloc:
            clean_path = parsed_url.path.strip("/")
            if clean_path and not re.search(r'[\d@]', clean_path):
                links.add("/" + clean_path)

    for match in re.findall(r'src=["\'](.*?)["\']', html_content):
        full_url = urljoin(base_url, match)
        parsed_url = urlparse(full_url)
        if parsed_url.netloc == urlparse(base_url).netloc:
            clean_path = parsed_url.path.strip("/")
            if clean_path and not re.search(r'[\d@]', clean_path):
                links.add("/" + clean_path)
    return links

def get_links_from_html_contents(path):
    full_url = domain + path
    print(f"[*] Crawling: {full_url}")
    try:
        result = subprocess.run(["curl", "-s", full_url], capture_output=True, text=True)
        if result.returncode == 0:
            return extract_links(result.stdout, domain)
    except Exception as e:
        print(f"[!] Error fetching {full_url}: {e}")
    return []

def check_leaf(text):
    # Define file extensions to consider as leaf nodes.
    extensions = {"png", "jpg", "svg", "pdf", "jpeg", "html", "css", "js", "php", "bmp", "gif"}
    if text.split(".")[-1].lower() in extensions:
        with leaf_lock:
            if text not in leaf_set:
                leaf_set.add(text)
        return True
    return False

def check_reachable(url):
    try:
        result = subprocess.run(
            ["curl", "-o", "/dev/null", "-s", "-w", "%{http_code}", url],
            capture_output=True, text=True, timeout=5
        )
        return int(result.stdout.strip()) not in [404, 403]
    except Exception as e:
        print(f"Error checking {url}: {e}")
        return False

def process_path(path):
    # Print in red for visibility
    print(f"\033[91m[*] Processing queue item: {path}\033[0m")
    dir_path = (domain + path).replace("//", "/")
    dirs = gobuster_scan(dir_path, dict_path)

    # Enqueue new paths from gobuster results
    for item in dirs:
        new_path = path + item
        with path_lock:
            if new_path not in visited_paths:
                print('\033[32m' + f"{domain+new_path}" + '\033[m')
                visited_paths.add(new_path)
                tasks_queue.put(new_path)

    # Process links from crawling
    links = get_links_from_html_contents(path)
    for link in links:
        if not check_leaf(link):
            parts = link.strip().split("/")[1:]
            new_path = ""
            for part in parts:
                new_path += "/" + part
                full_url = domain + new_path
                if not check_reachable(full_url):
                    pass
                else:
                    with path_lock:
                        if new_path not in visited_paths:
                            print('\033[32m' + f"{full_url}" + '\033[m')
                            visited_paths.add(new_path)
                            tasks_queue.put(new_path)

def worker_thread():
    # Continuously process tasks until the queue is empty.
    while True:
        try:
            path = tasks_queue.get(timeout=3)
        except queue.Empty:
            break
        process_path(path)
        tasks_queue.task_done()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dynamic Gobuster wrapper for threaded enumeration"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target website link")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-p", "--dict", required=True, help="Path to dictionary file")
    args = parser.parse_args()

    domain = args.domain
    dict_path = args.dict
    thread_count = args.threads

    # Thread-safe sets for tracking visited paths and leaf nodes.
    visited_paths = set()
    leaf_set = set()
    path_lock = threading.Lock()
    leaf_lock = threading.Lock()
    tasks_queue = queue.Queue()

    # Start with the root path
    visited_paths.add("")
    tasks_queue.put("")

    # Use ThreadPoolExecutor to create a pool with thread_count workers.
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        # Schedule worker threads
        futures = [executor.submit(worker_thread) for _ in range(thread_count)]
        # Wait for the tasks in the queue to be fully processed.
        tasks_queue.join()

    with open("result.txt", "w") as f:
        for path in visited_paths:
            f.write('\033[32m' + path + "\n")
        f.write("\n\n\n")
        for l in leaf_set:
            f.write('\033[91m' + l + "\n")
    print("[+] Enumeration complete. Results saved in 'result.txt'")
