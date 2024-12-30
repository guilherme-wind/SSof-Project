import sys
import os
import json
import esprima
from enum import Enum
from typing import List, Any, Dict, Tuple

class PresentIn(Enum):
    SOURCE = 1
    SINK = 2
    TAINTED = 3
    NONE = 4

results = []

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
        if "alternate" in node and node["alternate"] is not None:
            statement(node["alternate"])

    elif node["type"] == 'WhileStatement' or node["type"] == 'DoWhileStatement':
        # TODO
        expression(node["test"])
        statement(node["body"])
        return

    else:
        return


def expression(node: List[Dict[str, Any]]) -> Any:
    if node["type"] == 'UnaryExpression':
        expression(node["argument"])

    elif node["type"] == 'BinaryExpression':
        return binary_expr(node)
    
    elif node["type"] == 'AssignmentExpression':
        return assignment_expr(node)
    
    elif node["type"] == 'LogicalExpression':
        return
    
    elif node["type"] == 'MemberExpression':
        return
    
    elif node["type"] == 'CallExpression':
        return call_expr(node)
    
    elif node["type"] == 'Identifier':
        return node["name"]
    
    elif node["type"] == 'Literal':
        return node["value"]
    
    else:
        return

def assignment_expr(node):
    # list of variables on the left side
    result_left = expression(node['left'])

    # list of variables on the right side
    result_right = expression(node['right'])

    if result_left is None or result_right is None:
        return
    
    for right in [result_right] if isinstance(result_right, int) else result_right:
        current_line = node['loc']['start']['line']
        pattern_source: str = None

        tainted_source: List[Tuple[str, int]] = None

        # If worth to check the left side
        proceed: bool = False

        condition = ""

        # If the right side is a source
        if patterns.is_in_source(right) != []:
            pattern_source = right
            proceed = True
            condition += "source "
        # If the right side is a tainted variable
        taintvar = tainted_vars.is_in_tainted_vars(right)
        if taintvar != None:
            tainted_source = taintvar.get_sources()
            proceed = True
            condition += "tainted"
        
        # If right hand side is not a source or tainted variable
        if not proceed:
            continue
        
        for left in result_left:
            # If the left side is a sink
            patternvar = patterns.is_in_sink(left)
            if patternvar != []:
                # Register the vulnerability
                if "tainted" in condition:
                    for source in reversed(tainted_source):
                        results.append({
                            "vulnerability": f"A_{len(results) + 1}",
                            "source": [source[0], source[1]] if isinstance(source, tuple) else source,
                            "sink": [left, current_line],
                            "unsanitized_flows": "yes",
                            "sanitized_flows": [],
                            "implicit": "no"
                        })
                if "source" in condition:
                    results.append({
                        "vulnerability": f"A_{len(results) + 1}",
                        "source": [pattern_source, current_line],
                        "sink": [left, current_line],
                        "unsanitized_flows": "yes",
                        "sanitized_flows": [],
                        "implicit": "no"
                    })
            # If the left side is a tainted variable
            left_tainted = tainted_vars.is_in_tainted_vars(left)
            if left_tainted != None:
                # Update the source of the tainted variable
                if "source" in condition:
                    left_tainted.add_source((pattern_source, current_line))
                if "tainted" in condition:
                    for source in tainted_source:
                        left_tainted.add_source(source)
            # If left hand side is a 'clean' variable
            else:
                # It becomes a tainted variable
                tainted_var = TaintedVar(left)
                if "source" in condition:
                    tainted_var.add_source((pattern_source, current_line))
                if "tainted" in condition:
                    for source in tainted_source:
                        tainted_var.add_source(source)
                tainted_vars.add_tainted_var(tainted_var)

def call_expr(node) -> str:
    """
    Returns the name of the called function
    """
    callee_name: str = expression(node['callee'])
    arguments = []
    for arg in node['arguments']:
        arguments.append(expression(arg))

    # If there are no arguments, simply let the upper level handle it
    if arguments == []:
        return callee_name
    
    current_line = node['loc']['start']['line']
    callee_state = ""
    
    if patterns.is_in_sink(callee_name) != []:
        callee_state = "sink"
    if patterns.is_in_sanitizer(callee_name) != []:
        callee_state = "sanitizer"
    if patterns.is_in_source(callee_name) != []:
        callee_state = "source"

    # If there are arguments, check if they are tainted or contained in sources
    for arg in arguments:

        # If the argument is a tainted variable
        taintvar = tainted_vars.is_in_tainted_vars(arg)
        if taintvar != None:
            # If the callee is a sink
            if callee_state == "sink":
                for source in reversed(taintvar.get_sources()):
                    results.append({
                        "vulnerability": f"A_{len(results) + 1}",
                        "source": [source[0], source[1]] if isinstance(source, tuple) else source,
                        "sink": [callee_name, current_line],
                        "unsanitized_flows": "yes",
                        "sanitized_flows": [],
                        "implicit": "no"
                    })
            # If the callee is a source
            elif callee_state == "source":
                return
            # If the callee is a sanitizer
            elif callee_state == "sanitizer":
                for source in taintvar.get_sources():
                    sanitized_var = sanitized_vars.is_in_sanitized_vars(callee_name)
                    if sanitized_var != None:
                        sanitized_var.add_sanitizer(source)
                    else:
                        sanitized_var = SanitizedVar(callee_name)
                        sanitized_var.add_sanitizer(source)
                        sanitized_vars.add_sanitized_var(sanitized_var)

        # If the argument is in sources
        patternvar = patterns.is_in_source(arg)
        if patternvar != []:
            if callee_state == "sink":
                for source in reversed(patternvar):
                    results.append({
                        "vulnerability": f"A_{len(results) + 1}",
                        "source": [source, current_line],
                        "sink": [callee_name, current_line],
                        "unsanitized_flows": "yes",
                        "sanitized_flows": [],
                        "implicit": "no"
                    })
            elif callee_state == "source":
                return
    
    return [callee_name]


def binary_expr(node) -> str:
    return

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

    def add_source(self, source: Tuple[str, int]):
        """
        Add a source to the tainted variable. The source is a tuple
        (name of source in pattern, line of code).
        """
        if source not in self.source:
            self.source.append(source)
    
    def get_sources(self) -> List[Tuple[str, int]]:
        return self.source
# end class TaintedVar

class TaintedVarList:
    def __init__(self):
        self.tainted_vars = []

    def is_in_tainted_vars(self, var: str) -> TaintedVar | None:
        for tainted_var in self.tainted_vars:
            if tainted_var.get_name() == var:
                return tainted_var
        return None
    
    def add_tainted_var(self, name: str, source: Tuple[str, int]):
        """
        Add a tainted variable to the list. If the variable is already
        in the list, add the source to the variable.
        """
        taintvar = self.is_in_tainted_vars(name)
        if taintvar == None:
            tainted_var = TaintedVar(name)
            tainted_var.add_source(source)
            self.tainted_vars.append(tainted_var)
        else:
            tainted_var.add_source(source)
    
    def add_tainted_var(self, var: TaintedVar):
        self.tainted_vars.append(var)
    
    def get_tainted_var(self, name: str) -> TaintedVar:
        for var in self.tainted_vars:
            if var.get_name() == name:
                return var
        return None
# end class TaintedVarList

class Pattern:
    def __init__(self, name: str, source: List[str], sink: List[str], sanitizer: List[str]):
        self.name = name
        self.source = source
        self.sink = sink
        self.sanitizer = sanitizer

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
        return source in self.source
    
    def is_in_sanitizer(self, sanitizer: str) -> bool:
        return sanitizer in self.sanitizer
# end class Pattern
    
class PatternList:
    def __init__(self, patterns: List[str]):
        self.patterns = []
        for pattern in patterns:
            self.patterns.append(
                Pattern(
                    pattern["vulnerability"], 
                    pattern["sources"], 
                    pattern["sinks"],
                    pattern["sanitizers"]
                    )
                )
    
    def is_in_source(self, var: str) -> List[str]:
        """
        Check if the variable is in the source of the patterns.
        Returns a list of pattern names where the variable is 
        present in the source.
        """
        results = []
        for pattern in self.patterns:
            if pattern.is_in_source(var):
                results.append(pattern.get_name())
        return results
    
    def is_in_sink(self, var: str) -> List[str]:
        """
        Check if the variable is in the sink of the patterns.
        Returns a list of pattern names where the variable is 
        present in the sink.
        """
        results = []
        for pattern in self.patterns:
            if pattern.is_in_sink(var):
                results.append(pattern.get_name())
        return results
    
    def is_in_sanitizer(self, var: str) -> List[str]:
        """
        Check if the variable is in the sanitizer of the patterns.
        Returns a list of pattern names where the variable is 
        present in the sanitizer.
        """
        results = []
        for pattern in self.patterns:
            if pattern.is_in_sanitizer(var):
                results.append(pattern.get_name())
        return results
    
    def get_pattern(self, name: str) -> Pattern:
        for pattern in self.patterns:
            if pattern.get_name() == name:
                return pattern
        return None
# end class PatternList

class SanitizedVar:
    def __init__(self, name: str):
        self.name = name
        self.sanitizer = []
    
    def get_name(self) -> str:
        return self.name
    
    def add_sanitizer(self, sanitizer: Tuple[str, int]):
        """
        Add a sanitizer to the variable. The sanitizer is a tuple
        (name of sanitizer in pattern, line of code).
        """
        if sanitizer not in self.sanitizer:
            self.sanitizer.append(sanitizer)
    
    def get_sanitizers(self) -> List[Tuple[str, int]]:
        return self.sanitizer
# end class SanitizedVar

class SanitizedVarList:
    def __init__(self):
        self.sanitized_vars = []
    
    def is_in_sanitized_vars(self, var: str) -> SanitizedVar | None:
        for sanitized_var in self.sanitized_vars:
            if sanitized_var.get_name() == var:
                return sanitized_var
        return None
    
    def add_sanitized_var(self, name: str, sanitizer: Tuple[str, int]):
        """
        Add a sanitized variable to the list. If the variable is already
        in the list, add the sanitizer to the variable.
        """
        sanitized_var = self.is_in_sanitized_vars(name)
        if sanitized_var == None:
            sanitized_var = SanitizedVar(name)
            sanitized_var.add_sanitizer(sanitizer)
            self.sanitized_vars.append(sanitized_var)
        else:
            sanitized_var.add_sanitizer(sanitizer)
    
    def add_sanitized_var(self, var: SanitizedVar):
        self.sanitized_vars.append(var)
    
    def get_sanitized_var(self, name: str) -> SanitizedVar:
        for var in self.sanitized_vars:
            if var.get_name() == name:
                return var
        return None


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
# end class FileHandler

patterns: PatternList
tainted_vars: TaintedVarList = TaintedVarList()
sanitized_vars: SanitizedVarList = SanitizedVarList()
vulnerabilities: List[str] = []

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
            
    slice_code: str = FileHandler.load_file(slice_path)
    raw_patterns: str = json.loads(FileHandler.load_file(patterns_path))

    parsed_ast = esprima.parseScript(slice_code, loc=True).toDict()
    global patterns 
    patterns = PatternList(raw_patterns)

    analyze(parsed_ast)

    output_file = f"{FileHandler.extract_filename_without_extension(slice_path)}.output.json"
    FileHandler.save(output_file, results)
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()