import sys
import os
import json
import esprima


def load_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def analyze(slice_code, patterns):
    try:
        parsed_ast = esprima.parseScript(slice_code, loc=True).toDict()
    except Exception as e:
        print(f"Error parsing JavaScript slice: {e}")
        sys.exit(1)
    results = []
    for pattern in patterns:
        results.extend(vulnerabilities(parsed_ast, pattern))
    return results

def vulnerabilities(ast, pattern):
    sources = pattern["sources"]
    sinks = pattern["sinks"]
    sanitizers = pattern["sanitizers"]
    implicit = pattern.get("implicit", "no")
    tainted_vars = {}
    vulnerabilities = []
    #falta o resto...
    return vulnerabilities

def extract(node):
    if node["type"] == "Identifier":
        return node["name"]
    if node["type"] == "Literal":
        return node["value"]
    if node["type"] == "MemberExpression":
        object_name = extract(node["object"])
        property_name = extract(node["property"])
        return f"{object_name}.{property_name}"
    return None

def sanitized(arg, sanitizers):
    if arg["type"] == "CallExpression":
        function_name = extract(arg["callee"])
        return function_name in sanitizers
    return False

def save(output_path, results):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as file:
        json.dump(results, file, indent=4)

def main():
    if len(sys.argv) != 3:
        print("\033[31mError: Incorrect number of arguments.\033[0m")
        print("Example of how to call the program:")
        print("\033[32mUsage: python ./js_analyser.py <slice.js> <patterns.json>\033[0m\n")
        sys.exit(1)

    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]
    slice_name = os.path.basename(slice_path).rsplit('.', 1)[0]
    output_file = f"./output/{slice_name}.output.json"

    slice_code = load_file(slice_path)
    patterns = json.loads(load_file(patterns_path))

    results = analyze(slice_code, patterns)
    save(output_file, results)

if __name__ == "__main__":
    main()
