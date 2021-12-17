import json
import requests
from bs4 import BeautifulSoup
from urllib import parse

# filter by language and issue
def filter_data(data, lang, issue):
    issues = dict(
        xss = "Endpoints should not be vulnerable to reflected cross-site scripting (XSS) attacks",
        sqli = "Database queries should not be vulnerable to injection attacks"
    )
    langs = dict(
        php = "phpsecurity",
        java = "javasecurity"
    )
    collect = []
    for vuln in data:
        if vuln["language"] == langs[lang] and issues[issue] in vuln["rule_name"]:
            collect.append(vuln)
    return collect

# extract issues "id"
def get_id(issue):
    soup = BeautifulSoup(issue["issue_link"], "lxml")
    link = soup.find("a")["href"]
    return dict(parse.parse_qsl(parse.urlsplit(link).query))['issues']

def get_flows(issue_id):
    url = "https://sonarcloud.io/api/issues/search"
    params = dict(
        s = "FILE_LINE",
        issues = issue_id
    )
    resp = requests.get(url=url, params=params)
    flows = resp.json()
    if len(flows["issues"]) > 0:
        return flows["issues"][0]["flows"][0]["locations"]
    else:
        return []

def filter_flows(flows):
    """If there are two flows in the same line, take the one that includes the other
    """
    for ia, a in enumerate(flows):
        asl = a["textRange"]["startLine"]
        ael = a["textRange"]["endLine"]
        aso = a["textRange"]["startOffset"]
        aeo = a["textRange"]["endOffset"]
        for ib, b in enumerate(flows):
            bsl = b["textRange"]["startLine"]
            bel = b["textRange"]["endLine"]
            bso = b["textRange"]["startOffset"]
            beo = b["textRange"]["endOffset"]
            if ia == ib:
                continue
            # check if b is included in a
            if asl <= bsl and ael >= bel:
                if aso <= bso or aeo >= beo:
                    # remove b from list
                    del flows[ib]
    return flows

def get_code(issue_id):
    url = "https://sonarcloud.io/api/sources/issue_snippets"
    params = dict(
        issueKey = issue_id
    )
    resp = requests.get(url=url, params=params)
    return resp.json()

def clear_code(code):
    clear = {}
    for file, data in code.items():
        clear[file] = []
        for source in data['sources']:
            line = BeautifulSoup("<pre>" + source["code"] + "</pre>", "lxml").get_text().strip()
            clear[file].append(line)
    return clear

def get_taint(code, flow):
    # source code array
    file = flow["component"]
    sources = code[file]["sources"]
    # taint positions
    startLine = flow["textRange"]["startLine"]
    endLine = flow["textRange"]["endLine"]
    startOffset = flow["textRange"]["startOffset"]
    endOffset = flow["textRange"]["endOffset"]

    # if taint is over multiple line use array and "\n".join(array) later
    taint = []
    # build taint snippet based on flow and code
    # go through every line of the taint
    for line in range(startLine, endLine + 1, 1):
        # find/filter source code line for taint
        for source in sources:
            if source["line"] == line:
                # remove HTML markup. wrap in <pre> tag to preserve whitespaces
                code = BeautifulSoup("<pre>" + source["code"] + "</pre>", "lxml").get_text().strip()
                # apply offsets
                # if line == startLine and line == endLine:
                #     code = code[startOffset:endOffset]
                # elif line == startLine:
                #     code = code[startOffset:]
                # elif line == endLine:
                #     code = code[:endOffset]
                # else:
                #     code = code.strip()
                taint.append(code)
                # can break as lines are unique
                break
    return {
        "code": "\n".join(taint),
        "file": file
    }

def not_complete(code, flows):
    for flow in flows:
        if flow["component"] not in code:
            return True
    return False

def get_snippets(vulns):
    snippets = []
    for vuln in vulns:
        issid = get_id(vuln)
        print(issid)
        flows = get_flows(issid)
        flows = filter_flows(flows)
        code = get_code(issid)
        
        # check if code is complete
        if len(code) == 0 or not_complete(code, flows):
            continue

        snippet = []
        for flow in flows:
            taint = get_taint(code, flow)
            snippet.append(taint)

        if len(snippet) > 0:
            snippets.append({
                "taints": snippet,
                "id": issid,
                # "code": clear_code(code)
            })
    return snippets


def main():
    with open('../data/issues_merge.json') as json_file:
        data = json.load(json_file)
    
    snippets = []
    for vuln in ["sqli", "xss"]:
        vulns = filter_data(data, "java", vuln)
        snippets.extend(get_snippets(vulns))
    
    # filter duplicate snippets
    # snippets = list({tuple(v['taints']):v for v in snippets}.values())

    with open('../output/java/taints/java_taints.json', 'w', encoding='utf-8') as f:
        json.dump(snippets, f, ensure_ascii=False, indent=4)

if __name__ == "__main__":
    main()
