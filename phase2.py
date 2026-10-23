from datetime import datetime 
import email.utils
import feedparser
from db import get_connection, insert_incident
import requests
import re
import html

def collect_nvd(url):
    try:
        params = {
    "pubStartDate": "2026-09-01T00:00:00.000",
    "pubEndDate": "2026-09-20T23:59:59.999"
                }
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return []

    #print(response.text[:1000])
    try:
        data = response.json()
    except ValueError as e:
        print(f"Error parsing JSON from {url}: {e}")
        return []

    try:
        vulnerabilities = data["vulnerabilities"]
    except KeyError as e:
        print(f"Error extracting vulnerabilities from {url}: {e}")
        return []

    cyberwatchCollection=[]

    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cve")

        if not cve:
            print("Skipping vulnerability because CVE data is missing.")
            continue

        
        metrics = cve.get("metrics")

        if not metrics:
            print(f"Skipping {cve.get('id', 'unknown CVE')} because metrics are missing.")
            continue

        if "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
            cvss = metrics["cvssMetricV40"][0]
            version = "4.0"

        elif "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss = metrics["cvssMetricV31"][0]
            version = "3.1"

        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss = metrics["cvssMetricV30"][0]
            version = "3.0"

        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss = metrics["cvssMetricV2"][0]
            version = "2.0"

        else:
            continue

        if version == "2.0":
            severity = cvss.get("baseSeverity")
        else:
            severity = cvss.get("cvssData", {}).get("baseSeverity")

        score = cvss.get("cvssData", {}).get("baseScore")

        if severity is None or score is None:
            print(f"Skipping {cve.get('id', 'unknown CVE')} because CVSS data is incomplete.")
            continue

        descriptions = cve.get("descriptions")

        if not descriptions:
            print(f"Skipping {cve.get('id', 'unknown CVE')} because description is missing.")
            continue

        description = descriptions[0]

        configurations = cve.get("configurations", [])
        affected_products = []
        
        for configuration in configurations:
            nodes = configuration.get("nodes", [])
        
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                
                for cpe_match in cpe_matches:
                    criteria = cpe_match.get("criteria")
        
                    if criteria:
                        #print(criteria)
                        parts = criteria.split(":")
                        #print(parts)
    
                        if len(parts) >= 6:
                            vendor = parts[3]
                            product = parts[4]
                            cpe_version = parts[5]

                            if cpe_version == "*":
                                cpe_version = None

                            version_start_including = cpe_match.get("versionStartIncluding")
                            version_start_excluding = cpe_match.get("versionStartExcluding")
                            version_end_including = cpe_match.get("versionEndIncluding")
                            version_end_excluding = cpe_match.get("versionEndExcluding")

                            affected_product = {
                                "vendor": vendor,
                                "product": product,
                                "version": cpe_version,
                                "versionStartIncluding": version_start_including,
                                "versionStartExcluding": version_start_excluding,
                                "versionEndIncluding": version_end_including,
                                "versionEndExcluding": version_end_excluding
                            }

                            affected_products.append(affected_product)
        incident = {
            "title": cve.get("id"),
            "description": description.get("value"),
            "published":  cve.get("published"),
            "cvss_score": score,
            "severity": severity,
            "source": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
            "type": "vulnerability",
            "affected_products": affected_products,
            "product": affected_products[0].get("product") if affected_products else None
        }

        cyberwatchCollection.append(incident)

        if len(cyberwatchCollection) == 5:
            break

    return cyberwatchCollection

nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def collect_rss(url):
    try:
        feed = feedparser.parse(url)
        #print(f"Number of entries: {len(feed.entries)}")
        #print(feed.entries[0].title)
    except Exception as e:
        print(f"Failed to fetch feed: {e}")
        return []
    if feed and feed.bozo:
        print(f"Error parsing feed: {feed.bozo_exception}")
    if feed and not feed.entries:
        print("No entries found — skipping this source.")
        return []
    cyberwatchCollection = []
    for entry in feed.entries[:5]:
        try:
            incident = {
                
            "title": entry.title,
            "description": entry.summary,
            "url": entry.link,
            "published": entry.published,
            "cvss_score": None,
            "severity": None,
            "source": "The Hacker News",
            "type": "news"
                        }
            incident["description"] = html.unescape(incident["description"])
            cyberwatchCollection.append(incident)
        except Exception as e:
            print(f"Error occurred while processing entry: {e}")
            print("-" * 60)

        
    return cyberwatchCollection


rss_url = "https://feeds.feedburner.com/TheHackersNews"



def collect_cisa_kev(url):

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return []

    try:
        data = response.json()
    except ValueError as e:
        print(f"Error parsing JSON from {url}: {e}")
        return []

    try:
        vulnerabilities = data["vulnerabilities"]

    except KeyError as e:
        print(f"Error extracting vulnerabilities from {url}: {e}")
        return []

    cyberwatchCollection = []
    
    for vulnerability in vulnerabilities[:5]:

        incident = {
                "title": vulnerability.get("cveID"),
                "description": vulnerability.get("shortDescription"),
                "url": f"https://nvd.nist.gov/vuln/detail/{vulnerability.get('cveID')}",
                "published": None,
                "date_added": vulnerability.get("dateAdded"),
                "cvss_score": None,
                "severity": None,
                "source": "CISA KEV",
                "type": "known_exploited_vulnerability",
                "vendor": vulnerability.get("vendorProject"),
                "product": vulnerability.get("product"),
                "required_action": vulnerability.get("requiredAction"),
                "due_date": vulnerability.get("dueDate"),
                "ransomware_use": vulnerability.get("knownRansomwareCampaignUse")
                }
            
        cyberwatchCollection.append(incident)

    return cyberwatchCollection

cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

sources = [
    ("NVD", collect_nvd, nvd_url),
    ("The Hacker News", collect_rss, rss_url),
    ("CISA KEV", collect_cisa_kev, cisa_url)
]

cyberwatchCollection = []

for source_name, collector, url in sources:
    print(f"Collecting from {source_name}...")

    try:
        results = collector(url)
        cyberwatchCollection.extend(results)

        print(f"{source_name}: collected {len(results)} incidents")

    except Exception as e:
        print(f"{source_name}: collection failed: {e}")
        continue


print(f"Total incidents collected: {len(cyberwatchCollection)}")


def filter_incidents(incidents):
    filtered = []

    for incident in incidents:
        if not incident.get("title"):
            continue

        if not incident.get("description"):
            continue

        filtered.append(incident)

    return filtered


def get_cve_id(incident):
    title = incident.get("title", "")
    description = incident.get("description", "")

    match = re.search(r"CVE-\d{4}-\d{4,}", title, re.IGNORECASE)
    match2 = re.search(r"CVE-\d{4}-\d{4,}", description, re.IGNORECASE)

    if match:
        return match.group(0).upper()

    elif match2:
        return match2.group(0).upper()

    return None

def deduplicate_incidents(incidents):
    seen_cves = set()
    unique_incidents = []

    for incident in incidents:
        cve_id = get_cve_id(incident)

        if cve_id:
            if cve_id in seen_cves:
                continue

            seen_cves.add(cve_id)

        unique_incidents.append(incident)

    return unique_incidents



RELIVANT_KEYWORDS = [
    "vulnerability",
    "exploit",
    "breach",
    "flaws",
    "flaw",
    "vulnerabilities",
    "malware",
    "ransomware",
    "attackers",
    "hackers",
    "phishing",
    "cve",
    "compromise",
    "exploited",
]

def is_security_relevant(incident):
    if incident.get("source") == "CISA KEV":
        incident["relevant"] = True
    elif incident.get("source") == "NVD":
        incident["relevant"] = True
    elif incident.get("source") == "The Hacker News":
        title = incident.get("title") or ""
        description = incident.get("description") or ""

        text = (title + " " + description).lower()

        if any(keyword in text for keyword in RELIVANT_KEYWORDS):
            incident["relevant"] = True
        else:
            incident["relevant"] = False
    else:
        incident["relevant"] = False
    return incident["relevant"] 


RISK_KEYWORDS = [
    "zero-day",
    "actively exploited",
    "unauthenticated",
    "critical",
    "remote code execution",
    "rce",
    "run code as root",
    "arbitrary code",
    "full control",
    "full server control",
    "privilege escalation",
    "root access",
    "authentication bypass",
    "compromise",
    "exploited in the wild",
]

def keyword_score(incident):
        
    title = incident.get("title") or ""
    description = incident.get("description") or ""

    text = (title + " " + description).lower()

    if any(keyword in text for keyword in RISK_KEYWORDS):
        return 2

    return 0

   

def prioritize_incident(incident):
    priority = 0

    if incident.get("source") == "CISA KEV":
        priority += 3

    severity = str(incident.get("severity", "")).lower()

    if severity == "critical":
        priority += 3
    elif severity == "high":
        priority += 2
    elif severity == "medium":
        priority += 1

    else:
            priority += keyword_score(incident)

    if incident.get("ransomware_use") == "Known":
        priority += 2


    return priority


def get_priority_level(priority):
    if priority >= 5:
        return "Critical"
    elif priority >= 3:
        return "High"
    elif priority >= 1:
        return "Medium"
    else:
        return "Low"


Category_keyword = { "ransomware" : ["ransomware", "ransom"],
                     "breach" : [ "breach", "stolen data", "data leak"] , "malware" : ["malware", "trojan", "backdoor", "implant"], "vulnerability" : ["vulnerability", "cve", "flaw", "exploit"] }

def categorize_incident(incident):
    title = incident.get("title") or ""
    description = incident.get("description") or ""

    text = (title + " " + description).lower()
    if incident.get("type") == "known_exploited_vulnerability":
        incident["category"] = "vulnerability"
    elif incident.get("type") == "vulnerability":
        incident["category"] = "vulnerability"
    else:
        if any(keyword in text for keyword in Category_keyword["ransomware"]):
            incident["category"] = "ransomware"
        elif any(keyword in text for keyword in Category_keyword["breach"]):
            incident["category"] = "breach"
        elif any(keyword in text for keyword in Category_keyword["malware"]):
            incident["category"] = "malware"
        elif any(keyword in text for keyword in Category_keyword["vulnerability"]):
            incident["category"] = "vulnerability"
    return incident.get("category", "other")


def parse_date(date_string):
    if not date_string:
        return None

    try:
        return datetime.fromisoformat(date_string)
    except (ValueError, TypeError):
        pass

    try:
        return email.utils.parsedate_to_datetime(date_string)
    except (ValueError, TypeError):
        return None



for incident in cyberwatchCollection:
    incident["published"] = parse_date(incident.get("published"))
    incident["date_added"] = parse_date(incident.get("date_added"))
    incident["due_date"] = parse_date(incident.get("due_date"))
cyberwatchCollection = filter_incidents(cyberwatchCollection) #filter out incidents with missing title or description
cyberwatchCollection = [i for i in cyberwatchCollection if is_security_relevant(i)] #filter out incidents that are not security relevant
cyberwatchCollection = deduplicate_incidents(cyberwatchCollection)


for incident in cyberwatchCollection:
    incident["priority"] = prioritize_incident(incident)
    incident["priority_level"] = get_priority_level(incident["priority"])
    incident["category"] = categorize_incident(incident)


print(f"Incidents after filtering and deduplication: {len(cyberwatchCollection)}")


for item in cyberwatchCollection:

    print("-" * 60)

    print("Title:", item["title"])
    print("Source:", item["source"])
    print("Type:", item["type"])
    print("Published:", item["published"])
    print("Description:", item["description"])
    print("URL:", item["url"])
    print("Priority:", item["priority"])
    print("Priority Level:", item["priority_level"])
    print("Category:", item["category"])
    print("product:", item.get("product"))
    

conn = get_connection()
cursor = conn.cursor()


for incident in cyberwatchCollection:
    insert_incident(cursor, incident, get_cve_id(incident))

conn.commit()

    
cursor.execute("SELECT COUNT(*) FROM incidents;")
result = cursor.fetchone()
print(f"Current rows in incidents table: {result}")




