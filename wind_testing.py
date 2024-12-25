import sys
import os
import json
import esprima

# Load the content of a file and return it as a string
def load_file(file_path) -> str:
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

# Analyze the JavaScript slice for vulnerabilities using specified patterns
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
    """
    Analyze the AST for vulnerabilities based on the specified pattern.

    Args:
        ast (dict): The Abstract Syntax Tree (AST) of the JavaScript slice.
        pattern (dict): The pattern to match vulnerabilities.

    Returns:
        list: A list of detected vulnerabilities based on the pattern
    """
    sources = pattern["sources"]
    sinks = pattern["sinks"]
    sanitizers = pattern["sanitizers"]
    implicit = pattern.get("implicit", "no")

    tainted_vars = {} 
    vulnerabilities = [] 
    vulnerability_counter = 0  # Initialize the counter here

    # Recursively traverse AST nodes to identify tainted variables and vulnerabilities
    def traverse(node):
        """
        Recursively traverse the AST nodes to identify tainted variables and vulnerabilities.
        
        Args:
            node (dict): The current AST node to process.

        Returns:
            None
        """
        nonlocal vulnerability_counter  # Ensure the counter is accessible within the nested function

        if not isinstance(node, dict) or "type" not in node:
            return

        print(f"Processing Node: {node}")
        
        # Handle assignment expressions to propagate taint
        # E.e. var x = y;
        if node["type"] == "AssignmentExpression":
            left = extract(node["left"])
            right = node["right"]
            # Check if the right side of the assignment is a source or tainted variable
            # E.g. var x = y; where y is a source or tainted variable, then x is tainted
            if right["type"] == "Identifier" and right["name"] in sources:
                tainted_vars[left] = {"source": right["name"], "line": node["loc"]["start"]["line"]}
                print(f"Tainted Variable Added (Identifier): {left} = {tainted_vars[left]}")

            # Check if the right side of the assignment is a CallExpression with a source
            # E.g. var x = y(); where y() is a source, then x is tainted
            elif right["type"] == "CallExpression" and extract(right["callee"]) in sources:
                tainted_vars[left] = {"source": extract(right["callee"]), "line": node["loc"]["start"]["line"]}
                print(f"Tainted Variable Added (CallExpression): {left} = {tainted_vars[left]}")

            # Check if the right side of the assignment is a tainted variable
            # E.g. var x = y; where y is tainted, then x is tainted
            elif right["type"] == "Identifier" and right["name"] in tainted_vars:
                tainted_vars[left] = tainted_vars[right["name"]]
                print(f"Tainted Variable Propagated: {left} = {tainted_vars[left]}")

            # Check if the right side of the assignment is a MemberExpression with a tainted variable
            # E.g. var x = y.z; where y.z is tainted, then x is tainted
            elif right["type"] == "Literal":
                if right["value"] in tainted_vars:
                    tainted_vars[left] = tainted_vars[right["value"]]
                    print(f"Tainted Variable Propagated (Literal): {left} = {tainted_vars[left]}")
            
            # if x is in sinks, check if it is sanitized
            if left in sinks:
                sanitized_flow = []
                if sanitized(right, sanitizers):
                    sanitized_flow = [
                        [sanitize, node["loc"]["start"]["line"]] for sanitize in sanitizers
                    ]

                # Record the detected vulnerability
                vulnerability = {
                    "vulnerability": f"{pattern['vulnerability']}_{vulnerability_counter}",
                    "source": [tainted_vars[left]["source"], tainted_vars[left]["line"]],
                    "sink": [left, node["loc"]["start"]["line"]],
                    "unsanitized_flows": "no" if sanitized_flow else "yes",
                    "sanitized_flows": sanitized_flow,
                    "implicit": implicit
                }
                vulnerabilities.append(vulnerability)
                print(f"Detected Vulnerability: {vulnerability}")
                vulnerability_counter += 1

        # Handle function calls to identify flows into sinks
        if node["type"] == "CallExpression":
            function_name = extract(node["callee"])
            print(f"Analyzing Sink: {function_name} with args: {[extract(arg) for arg in node['arguments']]}")
            if function_name in sinks:
                for arg in node["arguments"]:
                    arg_name = extract(arg)
                    if arg_name in tainted_vars:
                        sanitized_flow = []
                        if sanitized(arg, sanitizers):
                            sanitized_flow = [
                                [sanitize, node["loc"]["start"]["line"]] for sanitize in sanitizers
                            ]

                        # Record the detected vulnerability
                        vulnerability = {
                            "vulnerability": f"{pattern['vulnerability']}_{vulnerability_counter}",
                            "source": [tainted_vars[arg_name]["source"], tainted_vars[arg_name]["line"]],
                            "sink": [function_name, node["loc"]["start"]["line"]],
                            "unsanitized_flows": "no" if sanitized_flow else "yes",
                            "sanitized_flows": sanitized_flow,
                            "implicit": implicit
                        }
                        vulnerabilities.append(vulnerability)
                        print(f"Detected Vulnerability: {vulnerability}")
                        vulnerability_counter += 1
                        
        # Recursively process child nodes
        for key, child in node.items():
            if isinstance(child, list):
                for subchild in child:
                    traverse(subchild)
            elif isinstance(child, dict):
                traverse(child)

    traverse(ast)
    print(f"\033[32mFinal Tainted Variables: {tainted_vars}\033[0m\n")
    print(f"\033[32mFinal Vulnerabilities: {vulnerabilities}\033[0m\n")
    return vulnerabilities

# Extract the name or value of a node for comparison
def extract(node):
    """
    Extract the name or value of a node for comparison.
    
    Args:
        node (dict): The AST node to extract the name or value from.
        
    Returns:
        str: The name or value of the node.
    """
    if node["type"] == "Identifier":
        return node["name"]
    if node["type"] == "Literal":
        return node["value"]
    if node["type"] == "MemberExpression":
        object_name = extract(node["object"])
        property_name = extract(node["property"])
        return f"{object_name}.{property_name}"
    return None

# Check if an argument is sanitized by one of the specified sanitizers
def sanitized(arg, sanitizers):
    if arg["type"] == "CallExpression":
        function_name = extract(arg["callee"])
        return function_name in sanitizers
    return False

# Save the analysis results to a JSON file
def save(output_path, results):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as file:
        json.dump(results, file, indent=4)

def main() -> int:
    if len(sys.argv) != 3:
        print("\033[31mError: Incorrect number of arguments.\033[0m")
        print("\033[32mUsage: python ./js_analyser.py <slice.js path> <patterns.json path>\033[0m\n")
        sys.exit(1)

    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]
    slice_name = os.path.basename(slice_path).rsplit('.', 1)[0]
    output_file = f"./output/{slice_name}.output.json"

    slice_code = load_file(slice_path)
    patterns = json.loads(load_file(patterns_path))

    results = analyze(slice_code, patterns)
    
    print("\033[34mDetected Vulnerabilities:\033[0m")
    print(json.dumps(results, indent=4))

    print(f"\033[32mSaving results to: {output_file}\033[0m")
    save(output_file, results)
    return 0;

if __name__ == "__main__":
    main()