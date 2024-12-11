import sys
import os
import json
import esprima

def load_file(file_path) -> str:
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
        result = vulnerabilities(parsed_ast, pattern)
        if result:
            results.extend(result)
    return results

def vulnerabilities(ast: dict, pattern: dict) -> list:
    sources = pattern["sources"]
    sinks = pattern["sinks"]
    sanitizers = pattern["sanitizers"]

    tainted_vars = {}
    vulnerabilities = []
    vulnerability_counter = 1

    def traverse(node):
        nonlocal vulnerability_counter

        if not isinstance(node, dict) or "type" not in node:
            return

        # Handle assignment expressions
        if node["type"] == "AssignmentExpression":
            left = extract(node["left"])
            right = node["right"]

            # Taint propagation logic (order matters)
            if right["type"] == "Identifier":
                if right["name"] in tainted_vars:
                    tainted_vars[left] = tainted_vars[right["name"]]
            elif right["type"] == "CallExpression" and extract(right["callee"]) in sources:
                tainted_vars[left] = {"source": extract(right["callee"]), "line": node["loc"]["start"]["line"]}
            elif right["type"] == "Identifier" and right["name"] in sources:
                tainted_vars[left] = {"source": right["name"], "line": node["loc"]["start"]["line"]}
            elif right["type"] == "Literal" and right["value"] == "":
                tainted_vars.pop(left, None)  # Clear taint for empty values
            else:
                tainted_vars.pop(left, None)  # Clear taint if assigned a safe value

            # Sink detection in assignment
            if left in sinks and left in tainted_vars:
                sanitized_flow = []
                if sanitized(right, sanitizers):
                    sanitized_flow = [
                        [sanitize, node["loc"]["start"]["line"]] for sanitize in sanitizers
                    ]
                vulnerability = {
                    "vulnerability": f"{pattern['vulnerability']}_{vulnerability_counter}",
                    "source": [tainted_vars[left]["source"], tainted_vars[left]["line"]],
                    "sink": [left, node["loc"]["start"]["line"]],
                    "unsanitized_flows": "no" if sanitized_flow else "yes",
                    "sanitized_flows": sanitized_flow,
                    "implicit": "no"
                }
                vulnerabilities.append(vulnerability)
                vulnerability_counter += 1

        # Handle function call sinks
        if node["type"] == "CallExpression":
            function_name = extract(node["callee"])
            if function_name in sinks:
                for arg in node["arguments"]:
                    arg_name = extract(arg)
                    if arg_name in tainted_vars:
                        sanitized_flow = []
                        if sanitized(arg, sanitizers):
                            sanitized_flow = [
                                [sanitize, node["loc"]["start"]["line"]] for sanitize in sanitizers
                            ]
                        vulnerability = {
                            "vulnerability": f"{pattern['vulnerability']}_{vulnerability_counter}",
                            "source": [tainted_vars[arg_name]["source"], tainted_vars[arg_name]["line"]],
                            "sink": [function_name, node["loc"]["start"]["line"]],
                            "unsanitized_flows": "no" if sanitized_flow else "yes",
                            "sanitized_flows": sanitized_flow,
                            "implicit": "no"
                        }
                        vulnerabilities.append(vulnerability)
                        vulnerability_counter += 1

        # Traverse child nodes
        for child in node.values():
            if isinstance(child, list):
                for subchild in child:
                    traverse(subchild)
            elif isinstance(child, dict):
                traverse(child)

    traverse(ast)
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
    return ""

def sanitized(arg, sanitizers):
    if arg["type"] == "CallExpression":
        function_name = extract(arg["callee"])
        return function_name in sanitizers
    return False

def save(output_path, results):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as file:
        json.dump(results, file, indent=4)

def main() -> int:
    if len(sys.argv) != 3:
        print("\033[31mError: Incorrect number of arguments.\033[0m")
        print("Example of how to call the program:")
        print("\033[32mUsage: python ./js_analyser.py <slice.js> <patterns.json>\033[0m\n")
        sys.exit(1)

    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]

    # Debugging: Print paths
    print(f"Slice path: {slice_path}")
    print(f"Patterns path: {patterns_path}")
    print(f"Current Working Directory: {os.getcwd()}")

    # Check if files exist
    if not os.path.exists(slice_path):
        print(f"Error: File not found -> {slice_path}")
        sys.exit(1)
    if not os.path.exists(patterns_path):
        print(f"Error: File not found -> {patterns_path}")
        sys.exit(1)

    slice_name = os.path.basename(slice_path).rsplit('.', 1)[0]
    output_file = f"./output/{slice_name}.output.json"

    slice_code = load_file(slice_path)
    patterns = json.loads(load_file(patterns_path))

    results = analyze(slice_code, patterns)

    print("\033[34mDetected Vulnerabilities:\033[0m")
    print(json.dumps(results, indent=4))

    print(f"\033[32mSaving results to: {output_file}\033[0m")
    save(output_file, results)
    return 0


if __name__ == "__main__":
    main()
