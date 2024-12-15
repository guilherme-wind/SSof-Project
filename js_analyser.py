import sys
import os
import json
import esprima
import logging
import argparse

# Safeguard to prevent infinite loops
MAX_CYCLE_ITERATIONS = 30

LOG_LEVELS = {
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}

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
        if node["type"] in ["IfStatement", "WhileStatement", "ForStatement"]:
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

def save(output_path, results):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as file:
        json.dump(results, file, indent=4)

def main() -> int:
    parser = argparse.ArgumentParser(description='Static analysis tool for identifying data and information flow violations')
    parser.add_argument('slice', help='JavaScript file to be analyzed', type=str)
    parser.add_argument('patterns', help='Patterns file to be checked', type=str)
    parser.add_argument('--log-level', default='INFO', help='Log level', choices=['INFO', 'DEBUG', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--log-file', default='./analyser.log', help='Log file location', type=str)
    parser.add_argument('--output-folder', default='./output', help='Output folder location', type=str)
    args = parser.parse_args()

    # Setup logging
    logging_level = LOG_LEVELS.get(args.log_level, logging.INFO)
    logging.basicConfig(filename=args.log_file, level=logging_level, format='%(asctime)s - %(levelname)s [%(funcName)s] %(message)s')
    logger = logging.getLogger()

    logger.info(f'Starting {parser.prog}')
    logger.debug(f'Arguments passed to js_analyser: {args}')

    slice_path = args.slice
    patterns_path = args.patterns

    # Debugging: Print paths
    print(f"Slice path: {slice_path}")
    print(f"Patterns path: {patterns_path}")
    print(f"Current Working Directory: {os.getcwd()}")

    # Check if files exist
    if not os.path.exists(slice_path):
        logger.error(f"Error: File not found -> {slice_path}")
        print(f"Error: File not found -> {slice_path}")
        sys.exit(1)
    if not os.path.exists(patterns_path):
        logger.error(f"Error: File not found -> {patterns_path}")
        print(f"Error: File not found -> {patterns_path}")
        sys.exit(1)

    slice_name = extract_filename_without_extension(slice_path)
    output_file = f"{args.output_folder}/{slice_name}.output.json"

    slice_code = load_file(slice_path)
    patterns = json.loads(load_file(patterns_path))

    results = analyze(slice_code, patterns)

    logger.info("Detected Vulnerabilities:")
    print("\033[34mDetected Vulnerabilities:\033[0m")
    print(json.dumps(results, indent=4))

    logger.info(f"Saving results to: {output_file}")
    print(f"\033[32mSaving results to: {output_file}\033[0m")
    make_folder_exist(args.output_folder)
    save(output_file, results)
    return 0

if __name__ == "__main__":
    main()