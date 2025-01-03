import sys
import os
import json
import esprima
from enum import Enum
from typing import List, Any, Dict, Optional, Tuple


class Taint:
    def __init__(self, source: str, line: int, pattern: str, implicit: bool = False):
        self.source = source
        self.line = line
        self.pattern = pattern
        self.implicit = implicit
        self.sanitizer: List[Tuple[str, int]] = []

    def add_sanitizer(self, sanitizer: Tuple[str, int]):
        """
        Add a sanitizer to the taint. The sanitizer is a tuple
        (name of sanitizer in pattern, line of code).
        """
        if sanitizer not in self.sanitizer:
            self.sanitizer.append(sanitizer)
    
    def copy(self) -> 'Taint':
        """
        Returns a deep copy of the Taint object.
        """
        copy = Taint(self.source, self.line, self.pattern, self.implicit)
        for sanitizer in self.sanitizer:
            copy.add_sanitizer(sanitizer)
        return copy
# end class Taint

class Variable: 
    """
    Represents an initialized variable in the piece of code, i.e. a variable
    within the scope.
    """
    def __init__(self, name: str, line: int):
        self.name = name
        self.initline = line
        self.taint: List[Taint] = []
    
    def get_name(self) -> str:
        return self.name
    
    def add_taint(self, source: str, line: int, pattern: str, implicit: bool = False):
        self.taint.append(Taint(source, line, pattern, implicit))

    def get_taint(self) -> List[Taint]:
        return self.taint

    def add_sanitizer(self, sanitizer: Tuple[str, int]):
        """
        Add a sanitizer to the variable. The sanitizer is a tuple
        (name of sanitizer in pattern, line of code).
        """
        for taint in self.taint:
            taint.add_sanitizer(sanitizer)
    
    def is_tainted(self) -> bool:
        return len(self.taint) > 0
    
    def copy(self) -> 'Variable':
        """
        Returns a deep copy of the Variable object.
        """
        copy = Variable(self.name, self.initline)
        for taint in self.taint:
            copy.add_taint(taint.copy())
        return copy
# end class Variable

class VariableList:
    def __init__(self):
        self.variables: List[Variable] = []
    
    def add_variable(self, variable: Variable):
        self.variables.append(variable)
    
    def is_in_variables(self, varname: str) -> Optional[Variable]:
        for variable in self.variables:
            if variable.name == varname:
                return variable
        return None

    def is_in_tainted_vars(self, varname: str) -> Optional[Variable]:
        for variable in self.variables:
            if variable.name == varname and variable.is_tainted():
                return variable
        return None
# end class VariableList

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


def list_merge(list1: list, list2: list) -> list:
    for element in list2:
        list1.append(element)
    return list1




def analyze(node):
    if not isinstance(node, dict) or "type" not in node:
        return
    
    if node["type"] == 'Program':
        for child in node["body"]:
            statement(child)

    return


def statement(node: List[Dict[str, Any]]):
    if node["type"] == 'ExpressionStatement':
        expression(node["expression"], [])

    elif node["type"] == 'BlockStatement':
        for child in node["body"]:
            statement(child)

    elif node["type"] == 'IfStatement':
        # TODO
        expression(node["test"], [])
        statement(node["consequent"])
        if node["alternate"] is not None:
            statement(node["alternate"])

    elif node["type"] == 'WhileStatement' | node["type"] == 'DoWhileStatement':
        # TODO
        expression(node["test"], [])
        statement(node["body"])
        return

    else:
        return



def expression(node: List[Dict[str, Any]], tainted: list) -> Any:
    if node["type"] == 'UnaryExpression':
        expression(node["argument"], tainted)

    elif node["type"] == 'BinaryExpression':
        return binary_expr(node, tainted)
    
    elif node["type"] == 'AssignmentExpression':
        return assignment_expr(node, tainted)
    
    elif node["type"] == 'LogicalExpression':
        return
    
    elif node["type"] == 'MemberExpression':
        return member_expr(node, tainted)
    
    elif node["type"] == 'CallExpression':
        return call_expr(node, tainted)
    
    elif node["type"] == 'Identifier':
        return identifier(node, tainted)
    
    elif node["type"] == 'Literal':
        return []
    
    else:
        return
    
def identifier(node, tainted: list) -> Variable:
    """
    Returns a variable object from the node.
    If the variable is not initialized, it will 
    have all the vulnerabilities.
    """
    var = variables.is_in_variables(node['name'])
    # If the variable has already been initialized
    if var != None:
        return var
    # Otherwise, it is uninitialized and have all vulnerabilities
    else:
        current_line = node['loc']['start']['line']
        var = Variable(node['name'], current_line)
        for pattern in patterns.patterns:
            var.add_taint(node['name'], current_line, pattern.name)
        return var

def member_expr(node, taint: list) -> List[Variable]:
    """
    """
    list: List[Variable] = []
    list_merge(list, expression(node['object'], []))
    list_merge(list, expression(node['property'], []))
    return list

def call_expr(node, taint: list) -> Any:
    callee_name = expression(node['callee'], [])
    arguments = []
    for arg in node['arguments']:
        arguments.append(expression(arg, []))

    for name in callee_name:
        for arg in arguments:
            if patterns.is_in_sink(name) != []:
                return


def assignment_expr(node, taint: list):
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
        # If the right side is an uninitialized variable

        # If the right side is a literal
        if right == 'Literal':
            proceed = True
            condition += "initialization"
        
        # If right hand side is not a source or tainted variable
        if not proceed:
            continue
        
        for left in result_left:
            # If the left side is a sink
            patternvar = patterns.is_in_sink(left)
            if patternvar != []:
                # Register the vulnerability
                if "tainted" in condition:
                    print("From tainted:")
                    for source in reversed(tainted_source):
                        print({
                            "vulnerability": patternvar,
                            "source": source,
                            "sink": left,
                            "line": current_line
                        })
                if "source" in condition:
                    print("From source:")
                    for source in reversed(pattern_source):
                        print({
                            "vulnerability": patternvar,
                            "source": (source, current_line),
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










def binary_expr(node) -> List[str]:
    list = []
    right_side = node['right']
    left_side = node['left']

    #It's not considering that it can be tainted sources, but I don't know how you want to do that
    if tainted_vars.is_in_tainted_vars(right_side):
        list.append(expression(right_side))
    return list



























def load_patterns(patterns: List[Dict[str, Any]]) -> None:
    for pattern in patterns:
        patterns.append(
            Pattern(
                pattern["vulnerability"], 
                pattern["sources"], 
                pattern["sinks"]
                )
            )
        




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
variables: VariableList = VariableList()
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