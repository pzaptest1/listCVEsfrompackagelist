import requests
import pandas as pd


def parse_oss_packages_from_spreadsheet(spreadsheet_path):
    df = pd.read_excel(spreadsheet_path)
    packages = df.values.tolist()

    for package in packages:
        package_name = str(package[0])
        package_version = str(package[1])
        print(f"Searching for CVEs in package: {package_name} {package_version}")

        cve_results = search_cves(package_name)
        if cve_results:
            for cve in cve_results:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                cvss = cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
                print(f"Package: {package_name} {package_version} | CVE: {cve_id} | CVSS: {cvss}")

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
spreadsheet_path = "path/to/your/spreadsheet.xlsx"
parse_oss_packages_from_spreadsheet(spreadsheet_path)
