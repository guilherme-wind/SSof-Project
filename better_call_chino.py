import sys
import os
import json
import esprima
from typing import List, Any, Dict

# Implementation of the pseudocode
def analyze(node: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(node, dict) or "type" not in node:
        return
    
    if node["type"] == 'Program':
        for child in node["body"]:
            statement(child)

    return


def statement(node: List[Dict[str, Any]]):
    if node["type"] == 'ExpressionStatement':
        expression(node["expression"])

    elif node["type"] == 'BlockStatement':
        for child in node["body"]:
            statement(child)

    elif node["type"] == 'IfStatement':
        # TODO
        expression(node["test"])
        statement(node["consequent"])
        if node["alternate"] is not None:
            statement(node["alternate"])

    elif node["type"] == 'WhileStatement' | node["type"] == 'DoWhileStatement':
        # TODO
        expression(node["test"])
        statement(node["body"])
        return

    else:
        return



def expression(node: List[Dict[str, Any]]):
    if node["type"] == 'UnaryExpression':
        expression(node["argument"])

    elif node["type"] == 'BinaryExpression':
        # TODO
        return
    
    elif node["type"] == 'AssignmentExpression':
        return
    
    elif node["type"] == 'LogicalExpression':
        return
    
    elif node["type"] == 'MemberExpression':
        return
    
    elif node["type"] == 'CallExpression':
        return
    
    elif node["type"] == 'Identifier':
        return
    
    elif node["type"] == 'Literal':
        return
    
    else:
        return



def assignment_expr(node):
    result_left = expression(node['left'])
    result_right = expression(node['right'])

















def load_patterns(patterns: List[Dict[str, Any]]) -> None:
    for pattern in patterns:
        patterns.append(
            Pattern(
                pattern["vulnerability"], 
                pattern["sources"], 
                pattern["sinks"]
                )
            )

class TaintedVar:
    def __init__(self, name: str):
        self.name = name
        self.source = []

    def __str__(self):
        return f"Variable: {self.name} - Source: {self.source}"
    
    def get_name(self) -> str:
        return self.name

    def add_source(self, source: str):
        self.source.append(source)

class Pattern:
    def __init__(self, name: str, source: List[str], sink: List[str]):
        self.name = name
        self.source = source
        self.sink = sink

    def __str__(self):
        return f"Vulnerability: {self.name}\nSource: {self.source}\nSink: {self.sink}\n"
    
    def get_name(self) -> str:
        return self.name
    
    def get_source(self) -> list:
        return self.source
    
    def get_sink(self) -> list:
        return self.sink
    
    def is_in_sink(self, sink: str) -> bool:
        return sink in self.sink
    
    def is_in_source(self, source: str) -> bool:
        return source in self.sources

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

patterns: List[Pattern] = []
tainted_vars: List[TaintedVar] = []
vulnerabilities: List[Pattern] = []

def main():
    slice_path = "./Examples/1-basic-flow/1b-basic-flow.js"
    patterns_path = "./Examples/1-basic-flow/1b-basic-flow.patterns.json"

    print(f"Analyzing slice: {slice_path}\nUsing patterns: {patterns_path}\n")

    slice_code = FileHandler.load_file(slice_path)
    patterns = json.loads(FileHandler.load_file(patterns_path))

    parsed_ast = esprima.parseScript(slice_code, loc=True).toDict()
    load_patterns(patterns)

    for vulnerability in patterns:
        print(vulnerability)
    
    results = analyze(slice_code)

    # print(f"\033[34mDetected Vulnerabilities:\033[0m\n{json.dumps(results, indent=4)}")

    # output_file = f"{FileHandler.extract_filename_without_extension(slice_path)}.output.json"
    # FileHandler.save(output_file, results)

if __name__ == "__main__":
    main()