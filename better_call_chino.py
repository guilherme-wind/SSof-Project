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



def expression(node: List[Dict[str, Any]]) -> Any:
    if node["type"] == 'UnaryExpression':
        expression(node["argument"])

    elif node["type"] == 'BinaryExpression':
        return
    
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
    
    for right in result_right:
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
            if patterns.is_in_sink(left) != []:
                if "source" in condition:
                    print("From source:")
                    print({
                        "vulnerability": patterns.is_in_sink(left),
                        "source": pattern_source,
                        "sink": left,
                        "line": current_line
                    })
                if "tainted" in condition:
                    print("From tainted:")
                    print({
                        "vulnerability": patterns.is_in_sink(left),
                        "source": tainted_source,
                        "sink": left,
                        "line": current_line
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
    # TODO: define return type


def call_expr(node):
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
        return
    if patterns.is_in_source(callee_name) != []:
        callee_state = "source"

    # If there are arguments, check if they are tainted or contained in sources
    for arg in arguments:
        # If the argument is in sources
        if patterns.is_in_source(arg) != []:
            # If the callee is a sink
            if callee_state == "sink":
                # Register the vulnerability
                print({
                    "vulnerability": patterns.is_in_sink(callee_name),
                    "source": arg,
                    "sink": callee_name,
                    "line": current_line
                })
            # If the callee is a source
            elif callee_state == "source":

                return 

        # If the argument is a tainted variable
        taintvar = tainted_vars.is_in_tainted_vars(arg)
        if taintvar != None:
            if callee_state == "sink":
                print({
                    "vulnerability": patterns.is_in_sink(callee_name),
                    "source": taintvar.get_sources(),
                    "sink": callee_name,
                    "line": current_line
                })
        
    
    return [callee_name, arguments]













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

class Pattern:
    def __init__(self, name: str, source: List[str], sink: List[str], sanitizer: List[str] = []):
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
        return source in self.source
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


class TaintedVarList:
    def __init__(self):
        self.tainted_vars = []

    def is_in_tainted_vars(self, var: str) -> TaintedVar | None:
        for tainted_var in self.tainted_vars:
            if tainted_var.get_name() == var:
                return tainted_var
        return None
    
    def add_tainted_var(self, name: str, source: Tuple[str, int]):
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
vulnerabilities: List[str] = []

def main():
    slice_path = "./Examples/1-basic-flow/1b-basic-flow.js"
    patterns_path = "./Examples/1-basic-flow/1b-basic-flow.patterns.json"

    print(f"Analyzing slice: {slice_path}\nUsing patterns: {patterns_path}\n")

    slice_code: str = FileHandler.load_file(slice_path)
    raw_patterns: str = json.loads(FileHandler.load_file(patterns_path))

    parsed_ast = esprima.parseScript(slice_code, loc=True).toDict()
    global patterns 
    patterns = PatternList(raw_patterns)

    analyze(parsed_ast)

    # print(f"\033[34mDetected Vulnerabilities:\033[0m\n{json.dumps(results, indent=4)}")

    # output_file = f"{FileHandler.extract_filename_without_extension(slice_path)}.output.json"
    # FileHandler.save(output_file, results)

if __name__ == "__main__":
    main()