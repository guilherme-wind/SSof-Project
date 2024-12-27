import sys
import os
import json
import esprima
from typing import List, Any, Dict

class FileHandler:
    @staticmethod
    def extract_filename_without_extension(file_path):
        return os.path.splitext(os.path.basename(file_path))[0]

    @staticmethod
    def load_file(file_path) -> str:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            sys.exit(f"Error: Failed to load file {file_path} - {e}")

    @staticmethod
    def save(output_path, data):
        output_directory = os.path.join("output", os.path.dirname(output_path) or "")
        os.makedirs(output_directory, exist_ok=True)
        final_path = os.path.join("output", output_path)
        with open(final_path, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4)
        print(f"Results saved to: {final_path}")

class PatternValidator:
    @staticmethod
    def validate_patterns(patterns):
        required_keys = {"sources", "sinks", "sanitizers", "vulnerability"}
        for index, pattern in enumerate(patterns, start=1):
            missing_keys = [key for key in required_keys if key not in pattern]
            if missing_keys:
                raise ValueError(f"Pattern at index {index} is missing required keys: {missing_keys}")

class ASTAnalyzer:
    def __init__(self, patterns: List[Dict[str, Any]]) -> None:
        self.patterns = patterns

    def analyze(self, slice_code: str) -> List[Dict[str, Any]]:
        try:
            parsed_ast = esprima.parseScript(slice_code, loc=True).toDict()
        except Exception as e:
            raise ValueError(f"Parsing JavaScript slice failed: {e}") from e

        results = [
            vulnerability
            for pattern in self.patterns
            for vulnerability in Vulnerability.find_vulnerabilities(parsed_ast, pattern) or []
        ]
        return results

class Vulnerability:
    @staticmethod
    def find_vulnerabilities(ast, pattern):
        sources = pattern["sources"]
        sinks = pattern["sinks"]
        sanitizers = pattern["sanitizers"]

        tainted_vars = {}  # Track tainted variables
        vulnerabilities = []
        vulnerability_counter = 1

        def traverse(node, implicit_context=False):
            nonlocal vulnerability_counter

            if not isinstance(node, dict) or "type" not in node:
                return

            # Handle AssignmentExpression
            if node["type"] == "AssignmentExpression":
                left = Utility.extract(node["left"])
                right = node["right"]

                # Taint propagation for variables
                if right["type"] == "Identifier":
                    if right["name"] in tainted_vars:
                        tainted_vars[left] = tainted_vars[right["name"]]
                    elif left in tainted_vars:
                        tainted_vars[right["name"]] = tainted_vars[left]
                elif right["type"] == "CallExpression" and Utility.extract(right["callee"]) in sources:
                    tainted_vars[left] = {"source": Utility.extract(right["callee"]), "line": node["loc"]["start"]["line"]}
                elif right["type"] == "Literal" and right["value"] == "":
                    tainted_vars.pop(left, None)
                else:
                    tainted_vars.pop(left, None)

                # Check for vulnerability when sink is found
                if left in sinks and left in tainted_vars:
                    sanitized_flow = Sanitization.collect_sanitizations(right, sanitizers)
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

            # Handle CallExpression (for nested calls like e(f(a)))
            if node["type"] == "CallExpression":
                function_name = Utility.extract(node["callee"])
                is_source = function_name in sources
                is_sanitizer = function_name in sanitizers
                arguments_tainted = []

                for arg in node["arguments"]:
                    arg_name = Utility.extract(arg)

                    # Propagate taint to arguments
                    if arg_name in tainted_vars:
                        tainted_vars[arg_name] = tainted_vars[arg_name]  # Propagate existing taint
                        arguments_tainted.append(arg_name)
                    elif is_source:
                        tainted_vars[arg_name] = {"source": function_name, "line": node["loc"]["start"]["line"]}
                        arguments_tainted.append(arg_name)

                    if is_sanitizer:
                        Sanitization.collect_sanitizations(arg, sanitizers)

                # Check sinks for each argument and capture vulnerabilities
                if function_name in sinks:
                    for arg_name in arguments_tainted:
                        if arg_name in tainted_vars:
                            sanitized_flow = Sanitization.collect_sanitizations(node, sanitizers)
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

            # Handle control structures (If, While, For, Switch)
            if node["type"] in ["IfStatement", "WhileStatement", "ForStatement", "SwitchStatement"]:
                if "consequent" in node:
                    traverse(node["consequent"], implicit_context=True)
                if "alternate" in node and node["alternate"]:
                    traverse(node["alternate"], implicit_context=True)
                if "body" in node:
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


class Sanitization:
    @staticmethod
    def collect_sanitizations(node, sanitizers):
        sanitization_flow = []
        if node["type"] == "CallExpression":
            function_name = Utility.extract(node["callee"])
            if function_name in sanitizers:
                sanitization_flow.append([function_name, node["loc"]["start"]["line"]])
            for arg in node["arguments"]:
                sanitization_flow.extend(Sanitization.collect_sanitizations(arg, sanitizers))
        return sanitization_flow

class Utility:
    @staticmethod
    def extract(node):
        if node["type"] == "Identifier":
            return node["name"]
        if node["type"] == "Literal":
            return node["value"]
        if node["type"] == "MemberExpression":
            object_name = Utility.extract(node["object"])
            property_name = Utility.extract(node["property"])
            return f"{object_name}.{property_name}"
        return ""

def main():
    if len(sys.argv) != 3:
        print(f"\033[31mError: Usage: python script.py <slice_path> <patterns_path>\033[0m", file=sys.stderr)
        sys.exit(1)

    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]

    print(f"Analyzing slice: {slice_path}\nUsing patterns: {patterns_path}\n")

    for path in [slice_path, patterns_path]:
        if not os.path.exists(path):
            print(f"\033[31mError: File not found -> {path}\033[0m", file=sys.stderr)
            sys.exit(1)

    slice_code = FileHandler.load_file(slice_path)
    patterns = json.loads(FileHandler.load_file(patterns_path))

    PatternValidator.validate_patterns(patterns)

    analyzer = ASTAnalyzer(patterns)
    results = analyzer.analyze(slice_code)

    print(f"\033[34mDetected Vulnerabilities:\033[0m\n{json.dumps(results, indent=4)}")

    output_file = f"{FileHandler.extract_filename_without_extension(slice_path)}.output.json"
    FileHandler.save(output_file, results)

if __name__ == "__main__":
    main()
