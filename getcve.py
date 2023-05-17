import requests


def parse_oss_packages(packages):
    for package in packages:
        print(f"Searching for CVEs in package: {package}")

        cve_results = search_cves(package)
        if cve_results:
            for cve in cve_results:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                cvss = cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
                print(f"Package: {package} | CVE: {cve_id} | CVSS: {cvss}")

        print("---")


def search_cves(package):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={package}"
    response = requests.get(url)
    if response.status_code == 200:
        json_data = response.json()
        return json_data.get('result', {}).get('CVE_Items', [])
    else:
        print(f"Error searching CVEs for package: {package}")
        return []


# Example usage
oss_packages = [
    "openssl v1.0.2",
    "openssl v1.1.1",
    "python 3.10",
    "Boost Libraries 1.74.0"
]
parse_oss_packages(oss_packages)

