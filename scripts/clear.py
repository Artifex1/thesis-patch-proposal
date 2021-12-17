import json
import re

def load_issues(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)

def clear_syntax(taint):
    """
    remove lost brackets
    add semicolon if not found
    """

    if taint == "}":
        return ""

    # remove "= "
    equalspace = re.compile("^(=\s*)")
    match = equalspace.match(taint)
    if match != None:
        taint = taint.replace(match.group(1), "")

    # add if infront of else
    ifelse = re.compile("^(else )")
    match = ifelse.match(taint)
    if match != None:
        taint = "if (false) {} " + taint

    # add try block to catch
    catch = re.compile("^(\} catch\()")
    match = catch.match(taint)
    if match != None:
        taint = "try {" + taint

    # Template Syntax to String
    syntax = re.compile("(?<=\$\{).+(?=\})|(?<=\<\%\=).+(?=\%\>)")
    if syntax.search(taint) != None:
        taint = "String test = \"" + taint.replace("\"", "\\\"") + "\";"

    # Remove extra closing brackets
    brackets = 0
    for index, char in enumerate(taint):
        if char == "(":
            brackets += 1
        if char == ")":
            brackets -= 1
        if brackets == -1:
            taint = taint[:index] + taint[index + 1:]
            brackets += 1
    if brackets > 0:
        taint += ")" * brackets
    
    # add semicolon if missing or closing bracket to opened bracket
    if any(string in taint for string in ["for", "if", "while", "try", "catch", "finally"]):
        # count { and add } accordingly
        brackets = 0
        nobracket = True
        for index, char in enumerate(taint):
            if char == "{":
                nobracket = False
                brackets += 1
            if char == "}":
                brackets -= 1
        if brackets > 0:
            taint += "}" * brackets
        elif nobracket and taint[-1] != ";":
            taint += "{}"
    else:
        # remove brackets where they don't belong
        brackets = taint.count("{") - taint.count("}")
        if brackets > 0:
            taint = taint.replace("{", "", brackets)
        if brackets < 0:
            taint = taint.replace("}", "", abs(brackets))

    taint = taint.strip()
    if len(taint) > 0:
        if taint[-1] != ";" and taint[-1] != "}":
            taint = taint + ";"

    return taint

def clear_issue(issue, remove_single_funcs=True, remove_double_funcs=True, tidy_syntax=True):
    """
    remove propagating functions
    """
    declaration = re.compile("^(?!(return|new)) *([a-zA-Z0-9<>\[\]._?, ]+) +([a-zA-Z0-9_]+) *\(")
    at = re.compile("^@.*")

    remainder = []
    taints = issue['taints']
    index = 0
    while index < len(taints):
        add = True
        # check for function
        func = declaration.match(taints[index]['code'])
        if func != None:
            func = func.group(3)
            if remove_single_funcs == True:
                add = False
            if index != len(taints) - 1:
                # check if function is called in next taint
                if func + "(" in taints[index + 1]['code']:
                    if remove_double_funcs == True:
                        add = False
                        index += 1
        
        # remove taints with @
        func_info = at.match(taints[index]['code'])
        if func_info != None:
            add = False

        if add:
            taint = taints[index]['code']
            if tidy_syntax:
                taint = clear_syntax(taint)
            if taint != "":
                remainder.append({
                    "code": taint,
                    "file": taints[index]['file']
                })

        index += 1
    return remainder


issues = load_issues('../patches/patched_taints_all.json')

for issue in issues:
    issue['cleared'] = clear_issue(issue, True, True, False)

with open('../output/java/taints/java_taints_patched.json', 'w', encoding="utf-8") as file:
    json.dump(issues, file, ensure_ascii=False, indent=4)
