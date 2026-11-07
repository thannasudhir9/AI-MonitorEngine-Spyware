import urllib.request
import json
import urllib.parse

def fetch_user_repos(username):
    url = f"https://api.github.com/users/{username}/repos?per_page=100"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 AegisShield-EDR/2.5"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"===============================================================")
            print(f"      PUBLIC REPOSITORIES FOR USER: {username.upper()}")
            print(f"===============================================================")
            print(f"Total Repositories: {len(data)}\n")
            for r in data:
                name = r.get("name", "")
                desc = r.get("description") or "No description"
                url = r.get("html_url", "")
                lang = r.get("language") or "N/A"
                stars = r.get("stargazers_count", 0)
                print(f"[*] {name:32} | {lang:10} | Stars: {stars:2} | {url}")
                print(f"    Description: {desc}")
    except Exception as e:
        print(f"Error fetching user repos: {e}")

def search_topic_repos(query, title):
    encoded = urllib.parse.quote(query)
    url = f"https://api.github.com/search/repositories?q={encoded}&sort=stars&per_page=5"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 AegisShield-EDR/2.5"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            items = data.get("items", [])
            print(f"\n===============================================================")
            print(f"      TOP GITHUB REPOSITORIES: {title.upper()}")
            print(f"===============================================================")
            for r in items:
                print(f"[*] {r.get('full_name')} (★ {r.get('stargazers_count'):,})")
                print(f"    URL:         {r.get('html_url')}")
                print(f"    Description: {r.get('description')}")
                print(f"    Language:    {r.get('language')} | License: {(r.get('license') or {}).get('spdx_id', 'N/A')}\n")
    except Exception as e:
        print(f"Error searching repos for {query}: {e}")

if __name__ == "__main__":
    fetch_user_repos("thannasudhir9")
    search_topic_repos("windows edr threat hunting", "Windows EDR & Threat Hunting")
    search_topic_repos("process monitor malware detection", "Process Monitoring & Malware Detection")
    search_topic_repos("python adblock proxy", "Python AdBlock & Network Interception")
