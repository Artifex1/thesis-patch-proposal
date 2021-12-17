import json
import re
import requests
from bs4 import BeautifulSoup
from pygments import highlight
from pygments.lexers import PhpLexer, Python3Lexer, RubyLexer, GoLexer, JavaLexer, JavascriptLexer
from pygments.formatters import HtmlFormatter

def get_function(string):
    """extract function name from string

    Args:
        string (string): line of code

    Returns:
        string: function name
    """
    first = re.search("\w+(?=\()", string)
    if first:
        return first.group()
    else:
        return ""

def replace_code(lang, code, replace_numbers = True, replace_vars = True, replace_strings = True):
    """Replace strings and vars and return their values

    Args:
        lang (string): programming language of the code
        code (string): line of code

    Returns:
        tuple: cleaned code, variables and strings
    """
    langs = {
        'python': {
            'integer': '.mi',
            'float': '.mf',
            'variable': '.n',
            'string1': '.s1',
            'string2': '.s2'
        },
        'php': {
            'integer': '.mi',
            'float': '.mf',
            'variable': '.nv',
            'string1': '.s1',
            'string2': '.s2'
        },
        'java': {
            'integer': '.mi',
            'float': '.mf',
            'variable': '.n',
            'string2': '.s',
        },
        'javascript': {
            'integer': '.mi',
            'float': '.mf',
            'variable': '.nx',
            'string1': '.s1',
            'string2': '.s2'
        },
        'ruby': {
            'integer': '.mi',
            'variable': '.n',
            'string1': '.s1',
            'string2': '.s2'
        },
        'go': {
            'integer': '.mi',
            'float': '.mf',
            'variable': '.nx',
            'string2': '.s'
        }
    }

    # remove double string escapes, newlines and tabulators
    # code = code.replace("\\", "")
    # code = code.replace("\"", "")
    # code = code.replace("\n", "")
    code = code.replace("\t", "")

    # check for template markup
    matches = re.findall("(?<=<%=)[\w\s\d]+(?=%>)", code)
    if len(matches) > 0:
        code = code.replace("\"", "\\\"")
        split = re.split("(?<=<%=)[\w\s\d]+(?=%>)", code)
        code = ""

        for i in range(len(matches)):
            code += "\"" + split[i] + "\"" + matches[i]
        code += "\"" + split[-1] + "\""


    # select language based parser
    if lang == 'php':
        html = highlight(code, PhpLexer(startinline = True), HtmlFormatter())
    elif lang == 'python':
        html = highlight(code, Python3Lexer(), HtmlFormatter())
    elif lang == 'java':
        html = highlight(code, JavaLexer(), HtmlFormatter())
    elif lang == 'javascript':
        html = highlight(code, JavascriptLexer(), HtmlFormatter())
    elif lang == 'ruby':
        html = highlight(code, RubyLexer(), HtmlFormatter())
    elif lang == 'go':
        html = highlight(code, GoLexer(), HtmlFormatter())    
    dom = BeautifulSoup("<pre>" + html + "</pre>", "lxml")

    # collect all strings and variable identifier for the context
    strings = []
    variables = []

    # replacements
    for key, value in langs[lang].items():
        items = dom.select(value)
        for item in items:
            if key == 'number' and replace_numbers:
                item.string = '1'
            elif key == 'float' and replace_numbers:
                item.string = '1.0'
            elif key == 'variable' and replace_vars:
                if lang == 'php':
                    # do not replace PHP sources
                    if item.string not in ['$_GET', '$_POST', '$_REQUEST', '$_SESSION', '$_COOKIE']:
                        variables.append(item.string)
                        item.string = '$variable'
                # exclude classes
                elif item.string[0].isupper():
                    continue
                else:
                    variables.append(item.string)
                    item.string = 'variable'
            elif key == 'string1' and replace_strings:
                strings.append(item.string.replace("\\", "")[1:-1])
                item.string = "'string'"
            elif key == 'string2' and replace_strings:
                strings.append(item.string.replace("\\", "")[1:-1])
                item.string = '"string"'
    
    # reembed string interpolation in surounded string.
    items = dom.select(".si")
    for item in items:
        prev = item.previous_sibling
        next = item.next_sibling
        if "string" in prev.string:
            prev.string = prev.string[:-1] + " "
        if "string" in next.string:
            next.string = " " + next.string[1:]

    return (dom.get_text().strip(), variables, strings)

def get_features(taints):
    """get featres for each code line of taints

    Args:
        taints (array): the lines of code to extract features

    Returns:
        dict: the features including func name, strings, vars and the cleaned code
    """
    features = {
        # "func": get_function(taints[0]),
        "strings": [],
        "variables": [],
        "cleaned": []
    }

    taints = [taint['code'] for taint in taints]
    for taint in taints:
        (cleaned, variables, strings) = replace_code('java', taint, False, True, False)
        features["strings"].extend(strings)
        features["variables"].extend(variables)
        features["cleaned"].append(cleaned)
    
    return features

def get_full_code(file):
    url = "https://sonarcloud.io/api/sources/lines"
    params = dict(
        key = file
    )
    resp = requests.get(url=url, params=params)
    sources = resp.json()['sources']
    sources = [source['code'] for source in sources]
    sources = "\n".join(sources)

    sources = BeautifulSoup("<pre>" + sources + "</pre>", "lxml").get_text()
    # strip each line as taints are also stripped
    sources = sources.split("\n")
    sources = [source.strip() for source in sources]
    sources = "\n".join(sources)
    
    return sources

def script_context(taint):
    """
    load file from api
    apply regex to check for script tag
    find taint in regex result
    return true/false
    """
    scripttag = re.compile("(?<=<script)(.|\n)+?(?=<\/script>)")
    fullcode = get_full_code(taint['file'])
    findings = scripttag.finditer(fullcode)
    for finding in findings:
        if taint['code'] in finding.group(0):
            return True
    return False

def code_category(taints):
    category = 0x00

    # toString
    sb = re.compile("\.toString\(\)")
    # Template Syntax
    ts = re.compile("(?<=\$\{)(.|\n)+?(?=\})|(?<=\<\%\=)(.|\n)+?(?=\%\>)")
    # String Concatenation
    sc = re.compile('(".+")\s*\n*\s*\+\s*\n*\s*(\w+)|(\w+)\s*\n*\s*\+\s*\n*\s*(\w+)|(\w+)\s*\n*\s*\+\s*\n*\s*(".+")')

    for taint in taints:
        if sb.search(taint['code']) != None:
            category |= 0x01
        if ts.search(taint['code']) != None:
            if script_context(taint) or "javaScript:onClick" in taint['code']:
                category |= 0x04
            else:
                category |= 0x02
        if "format(" in taint['code'] or "printf(" in taint['code']:
            category |= 0x08
        if sc.search(taint['code']) != None:
            category |= 0x10
    return category

with open('../output/java/taints/java_taints_cleaned.json', encoding="utf-8") as json_file:
    data = json.load(json_file)

    for snippet in data:
        snippet["features"] = get_features(snippet["taints"])
        snippet["category"] = code_category(snippet["cleared"])

    with open('../output/java/taints/java_taint_features.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
