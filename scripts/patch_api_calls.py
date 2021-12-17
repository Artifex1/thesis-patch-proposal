import requests
import base64
import json

headers = {'Authorization': 'token <GITHUB TOKEN>'}

def get_orgs(start, end, step):
    # collect orgs from SonarCloud
    orgs = []
    for page in range(start, end):
        a = requests.get(f'https://sonarcloud.io/api/organizations/search?p={page}&ps={step}').json()
        orgs.extend(a['organizations'])
    return orgs

def get_fixed(org):
    issues = requests.get(f'https://sonarcloud.io/api/issues/search?languages=java&cwe=79,89&sonarsourceSecurity=sql-injection,xss&severities=BLOCKER,CRITICAL&resolutions=FIXED&organization={org}').json()
    if 'issues' in issues and len(issues['issues']) > 0:
        return issues['issues']
    else:
        return False

def get_owner_repo(project):
    info = requests.get(f'https://sonarcloud.io/api/navigation/component?component={project}').json()
    if 'alm' in info and 'github' in info['alm']['url']:
        (owner, repo) = info['alm']['url'].replace("https://github.com/", "").split("/")
        return (owner, repo)
    else:
        return (False, False)

def filter_flows(flows):
    """If there are two flows in the same line, take the one that includes the other
    """
    for ia, a in enumerate(flows):
        asl = a["textRange"]["startLine"]
        ael = a["textRange"]["endLine"]
        for ib, b in enumerate(flows):
            bsl = b["textRange"]["startLine"]
            bel = b["textRange"]["endLine"]
            if ia == ib:
                continue
            # check if b lines of code is included in a
            if asl <= bsl and ael >= bel:
                # remove b from list
                del flows[ib]
    return flows

def save_results(results):
    with open("./patches/patched_taints.json", "w", encoding="utf-8") as file:
        json.dump(results, file)
        print("Results Saved.")

results = []

orgs = get_orgs(1, 100, 500)
for count, scorg in enumerate(orgs):
    if count % 500 == 0:
        print(f"Number of checked SC Orgs: {count}")
        save_results(results)
    
    # get all FIXED Java XSS and SQLi issues from an org
    fixed = get_fixed(scorg['key'])
    if fixed == False:
        continue
    
    print(f"Org with FIXED Java XSS or SQLi issues: {scorg['key']}")

    for fix in fixed:
        key = fix['key']
        project = fix['project']
        updateDate = fix['updateDate']
        component = fix['component']
        reportFile = component.replace(project + ":", "")

        if 'flows' not in fix or len(fix['flows']) < 1:
            continue

        (owner, repo) = get_owner_repo(project)
        if (owner == False or repo == False):
            print(f"Probably not using GitHub: {project}")
            break

        # get patch commit hash
        commits_request = requests.get(f'https://api.github.com/repos/{owner}/{repo}/commits?until={updateDate}&path={reportFile}', headers=headers)
        # commits_request = requests.get(f'https://api.github.com/repos/{owner}/{repo}/commits?until={updateDate}', headers=headers)
        commits = commits_request.json()
        status  = commits_request.status_code

        if status == 403:
            print("GitHub API limit reached.")
            print(f"Number of checked SC Orgs: {count}")
            save_results(results)
            quit()
        elif len(commits) == 0 or status == 404:
            print(f"No suitable commit found for: {project} - {key}")
            break
        
        if len(commits[0]['parents']) == 0:
            continue
        patchHash = commits[0]['sha']
        vulnHash = commits[0]['parents'][0]['sha']

        # fetch source code from github and apply locations to receive taint flow steps
        locations = filter_flows(fix['flows'][0]['locations'])
        taints = []
        contents = {}
        # print(key, locations)
        for taint in locations:
            # get file content
            if 'component' not in taint:
                continue
            file = taint['component'].replace(project + ":", "")

            if file not in contents:
                content_request = requests.get(f'https://api.github.com/repos/{owner}/{repo}/contents/{file}?ref={vulnHash}', headers=headers)
                if content_request.status_code == 404:
                    continue
                contents[file] = base64.b64decode(content_request.json()['content']).decode("utf-8").replace("\t", "").split("\n")

            content = contents[file]
            code = []
            
            if taint['textRange']['endLine'] > len(content):
                break
            for line in range(taint['textRange']['startLine'], taint['textRange']['endLine'] + 1):
                code.append(content[line - 1].strip())
            code = "\n".join(code)
            taints.append({
                "file": taint['component'],
                "code": code,
                "lines": str(taint['textRange']['startLine']) + "-" + str(taint['textRange']['endLine'])
            })
        
        result = {
            "taints": taints,
            "id": fix['key'],
            "patchHash": patchHash,
            "vulnHash": vulnHash,
            "rule": fix['rule'],
            "owner": owner,
            "repo": repo
        }
        print(result)
        results.append(result)

save_results(results)