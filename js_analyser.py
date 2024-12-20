import sys
import os
import json
import esprima
import logging
import argparse

def make_folder_exist(folder):
    """
    Creates the specified folder if it doesn't exist
    """
    os.makedirs(folder, exist_ok=True)

def extract_filename_without_extension(file_path):
    """
    Returns the filename without the path and extension
    """
    return os.path.splitext(os.path.basename(file_path))[0]

def load_file(file_path) -> str:
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        logging.error(f"Failed to load file {file_path}: {e}")
        sys.exit(1)

def validate_patterns(patterns):
    """
    Validates the structure of the patterns file.
    Raises ValueError if the required keys are missing or invalid.
    """
    required_keys = {"sources", "sinks", "sanitizers", "vulnerability"}
    for index, pattern in enumerate(patterns, start=1):
        missing_keys = required_keys - pattern.keys()
        if missing_keys:
            raise ValueError(f"Pattern at index {index} is missing required keys: {missing_keys}")

def analyze(slice_code, patterns):
    try:
        parsed_ast = esprima.parseScript(slice_code, loc=True).toDict()
    except Exception as e:
        logging.error(f"Error parsing JavaScript slice: {e}")
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

    def traverse(node, implicit_context=False):
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
            elif right["type"] == "Literal" and right["value"] == "":
                tainted_vars.pop(left, None)  # Clear taint for empty values
            else:
                tainted_vars.pop(left, None)  # Clear taint if assigned a safe value

            # Sink detection in assignment
            if left in sinks and left in tainted_vars:
                sanitized_flow = []
                sanitization_results = collect_sanitizations(right, sanitizers)
                if sanitization_results:
                    sanitized_flow = sanitization_results
                vulnerability = {
                    "vulnerability": f"{pattern['vulnerability']}_{vulnerability_counter}",
                    "source": [tainted_vars[left]["source"], tainted_vars[left]["line"]],
                    "sink": [left, node["loc"]["start"]["line"]],
                    "unsanitized_flows": "no" if sanitized_flow else "yes",
                    "sanitized_flows": sanitized_flow,
                    "implicit": "yes" if implicit_context else "no"
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
                        sanitization_results = collect_sanitizations(arg, sanitizers)
                        if sanitization_results:
                            sanitized_flow = sanitization_results
                        vulnerability = {
                            "vulnerability": f"{pattern['vulnerability']}_{vulnerability_counter}",
                            "source": [tainted_vars[arg_name]["source"], tainted_vars[arg_name]["line"]],
                            "sink": [function_name, node["loc"]["start"]["line"]],
                            "unsanitized_flows": "no" if sanitized_flow else "yes",
                            "sanitized_flows": sanitized_flow,
                            "implicit": "yes" if implicit_context else "no"
                        }
                        vulnerabilities.append(vulnerability)
                        vulnerability_counter += 1

        # Handle control flow structures for implicit taint tracking
        if node["type"] in ["IfStatement", "WhileStatement", "ForStatement", "SwitchStatement"]:
            if "consequent" in node:  # IfStatement
                traverse(node["consequent"], implicit_context=True)
            if "alternate" in node and node["alternate"]:  # IfStatement with else block
                traverse(node["alternate"], implicit_context=True)
            if "body" in node:  # Loops
                traverse(node["body"], implicit_context=True)

        # Traverse child nodes
        for child in node.values():
            if isinstance(child, list):
                for subchild in child:
                    traverse(subchild, implicit_context)
            elif isinstance(child, dict):
                traverse(child, implicit_context)

    traverse(ast)
    return vulnerabilities

def collect_sanitizations(node, sanitizers):
    sanitization_flow = []
    if node["type"] == "CallExpression":
        function_name = extract(node["callee"])
        if function_name in sanitizers:
            sanitization_flow.append([function_name, node["loc"]["start"]["line"]])
        for arg in node["arguments"]:
            sanitization_flow.extend(collect_sanitizations(arg, sanitizers))
    return sanitization_flow

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

def save(output_path, data):
    """
    Save data to the specified output path, ensuring it is saved inside an 'output' folder.
    """
    output_directory = os.path.join("output", os.path.dirname(output_path) or "")
    os.makedirs(output_directory, exist_ok=True)
    final_path = os.path.join("output", output_path)
    with open(final_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4)

    print(f"Results saved to: {final_path}")


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"js_analyser.py: error: {message}\n")
        sys.exit(2)

def main():
    """
    Main function for analyzing JavaScript files with defined patterns.
    """
    parser = argparse.ArgumentParser(description="Static analysis tool for identifying data and information flow violations")
    parser.add_argument('slice', help='JavaScript file to analyze')
    parser.add_argument('patterns', help='JSON file with analysis patterns')
    args = parser.parse_args()

    slice_path, patterns_path = args.slice, args.patterns
    print(f"Analyzing slice: {slice_path}\nUsing patterns: {patterns_path}\n")

    # Validate input files
    for path in [slice_path, patterns_path]:
        if not os.path.exists(path):
            sys.exit(f"Error: File not found -> {path}")

    # Load data
    slice_code = load_file(slice_path)
    patterns = json.loads(load_file(patterns_path))
    validate_patterns(patterns)

    # Analyze and display results
    results = analyze(slice_code, patterns)
    print(f"\033[34mDetected Vulnerabilities:\033[0m\n{json.dumps(results, indent=4)}")

    # Save results
    output_file = f"{extract_filename_without_extension(slice_path)}.output.json"
    print(f"\033[32mResults saved to: {output_file}\033[0m")
    save(output_file, results)

if __name__ == "__main__":
    main()
