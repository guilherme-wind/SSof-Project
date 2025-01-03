import sys
import os
import json
import esprima
from enum import Enum
from typing import List, Any, Dict, Optional, Tuple

from traducao_pseudocodigo import sources


class InitializedVar:
    """
    A class that represents a variable that has been initialized.
    It contains the name of the variable and the line of code where
    it was initialized.
    It also contains a list of subvariables of the initialized variable.
    E.g.:
        `var a = [];`
        `a[b] = 1;`
        `b` is a subvariable of `a` and both are initialized.

    Each subvariable can also have subvariables. So the class is recursive.
    """
    def __init__(self, name: str, line: int):
        """
        Parameters:
        name (str): the name of the variable
        line (int): the line of code where the variable was FIRSTLY initialized
        """
        self.name = name
        self.line = line
        self.subvar: List[InitializedVar] = []
    
    def get_name(self) -> str:
        return self.name
    
    def get_line(self) -> int:
        return self.line
    
    def add_subvar(self, subvar: 'InitializedVar'):
        self.subvar.append(subvar)
    
    def add_subvar(self, name: str, line: int) -> 'InitializedVar':
        subvar = InitializedVar(name, line)
        self.subvar.append(subvar)
        return subvar

    def get_subvar(self) -> List['InitializedVar']:
        return self.subvar
    
    def is_in_subvar(self, name: str) -> Optional['InitializedVar']:
        """
        1 level search for a subvariable with the given name.
        """
        for subvar in self.subvar:
            if subvar.get_name() == name:
                return subvar
        return None
    
    def is_in_subvar(self, name: List[str]) -> Optional['InitializedVar']:
        """
        Check if the variable is in the subvariables of the initialized variable.
        Returns the subvariable if it is present in the subvariables.
        E.g.: if the variable a has b and b has c, when calling a.is_in_var(["b", "c"]),
        it will return the subvariable c.
        """
        for subvar in self.subvar:
            if subvar.get_name() == name[0]:
                if len(name) == 1:
                    return subvar
                else:
                    return subvar.is_in_subvar(name[1:])
        return None
# end class InitializedVar

class InitializedVarList:
    def __init__(self):
        self.initialized_vars: List[InitializedVar] = []
    
    def is_in_initialized_vars(self, var: List[str]) -> InitializedVar | None:
        """
        Check if the variable is in the initialized variables list.
        Returns the variable if it is present in the list.
        """
        for initialized_var in self.initialized_vars:
            if initialized_var.get_name() == var[0]:
                if len(var) == 1:
                    return initialized_var
                else:
                    return initialized_var.is_in_subvar(var[1:])
        return None
    
    def add_initialized_var(self, name: str, line: int) -> 'InitializedVar':
        """
        Add a new initialized variable to the list and return it.
        If the variable is already in the list, will return the existing
        variable.
        """
        initialized_var = self.is_in_initialized_vars(name)
        if initialized_var == None:
            initialized_var = InitializedVar(name, line)
            self.initialized_vars.append(initialized_var)
        return initialized_var
# end class InitializedVarList

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
    
    def copy(self) -> 'TaintedVar':
        """
        Returns a copy of the TaintedVar object.
        """
        copy = TaintedVar(self.name)
        for source in self.source:
            copy.add_source(source)
        return copy
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
        """
        Add a sanitized variable to the list. Recommended
        to use the add_sanitized_var(self, name, sanitizer)
        """
        self.sanitized_vars.append(var)
    
    def get_sanitized_var(self, name: str) -> SanitizedVar:
        for var in self.sanitized_vars:
            if var.get_name() == name:
                return var
        return None
# end class SanitizedVarList

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



def expression(node: List[Dict[str, Any]], tainted: list) -> Any:
    if node["type"] == 'UnaryExpression':
        expression(node["argument"])

    elif node["type"] == 'BinaryExpression':
        return binary_expr(node)
    
    elif node["type"] == 'AssignmentExpression':
        return assignment_expr(node)
    
    elif node["type"] == 'LogicalExpression':
        return
    
    elif node["type"] == 'MemberExpression':
        return member_expr(node)
    
    elif node["type"] == 'CallExpression':
        return call_expr(node, tainted)
    
    elif node["type"] == 'Identifier':
        return node["name"]
    
    elif node["type"] == 'Literal':
        return 'Literal'
    
    else:
        return
    
def identifier(node, tainted: list):
    return [tainted_vars.is_in_tainted_vars(node['name'])]



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


def call_expr(node, taint: list) -> Any:
    callee_name = expression(node['callee'])
    arguments = []
    for arg in node['arguments']:
        arguments.append(expression(arg))

    for name in callee_name:
        for arg in arguments:
            if patterns.is_in_sink(name) != []:
                return














    # # If there are no arguments, simply let the upper level handle it
    # if arguments == []:
    #     return callee_name
    
    # current_line = node['loc']['start']['line']
    # callee_state = ""
    
    # if patterns.is_in_sink(callee_name) != []:
    #     callee_state = "sink"
    # if patterns.is_in_sanitizer(callee_name) != []:
    #     callee_state = "sanitizer"
    # if patterns.is_in_source(callee_name) != []:
    #     callee_state = "source"

    # # If there are arguments, check if they are tainted or contained in sources
    # for arg in arguments:

    #     # If the argument is a tainted variable
    #     taintvar = tainted_vars.is_in_tainted_vars(arg)
    #     if taintvar != None:
    #         # If the callee is a sink
    #         if callee_state == "sink":
    #             # Register the vulnerability
    #             print("From tainted:")
    #             # Reverse the order to get first added register first
    #             for source in reversed(taintvar.get_sources()):
    #                 print({
    #                     "vulnerability": patterns.is_in_sink(callee_name),
    #                     "source": source,
    #                     "sink": callee_name,
    #                     "line": current_line
    #                 })
    #         # If the callee is a source
    #         elif callee_state == "source":
    #             # TODO
    #             return
    #         # If the callee is a sanitizer
    #         elif callee_state == "sanitizer":
    #             sanitezed_var = sanitized_vars.is_in_sanitized_vars(arg)
    #             if sanitezed_var != None:
    #                 sanitezed_var.add_sanitizer((callee_name, current_line))
    #             else:
    #                 sanitezed_var = SanitizedVar(arg)
    #                 sanitezed_var.add_sanitizer((callee_name, current_line))
    #                 sanitized_vars.add_sanitized_var(sanitezed_var)

    #     # If the argument is in sources
    #     patternvar = patterns.is_in_source(arg)
    #     if patternvar != []:
    #         # If the callee is a sink
    #         if callee_state == "sink":
    #             # Register the vulnerability
    #             print("From source:")
    #             # Reverse the order to get first added register first
    #             for source in reversed(patternvar):
    #                 print({
    #                     "vulnerability": patterns.is_in_sink(callee_name),
    #                     "source": source,
    #                     "sink": callee_name,
    #                     "line": current_line
    #                 })
    #         # If the callee is a source
    #         elif callee_state == "source":
    #             # TODO
    #             return 
    # return [callee_name]




def member_expr(node, taint: list) -> List[str]:
    list = []
    list.append(expression(node['object']))
    list.append(expression(node['property']))
    #if the goal is to return a list with tainted variables
    for element in list:
        #if at least one of the variables in the list is tainted, then all of them should be tainted right?
        if patterns.is_in_source(element) != []:
            return list
        elif tainted_vars.is_in_tainted_vars(element) != []:
            return list
        else:
            return [] # means this whole recursive member expression did not touch any
    return list


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
initialized_vars: InitializedVarList = InitializedVarList()
tainted_vars: TaintedVarList = TaintedVarList()
sanitized_vars: SanitizedVarList = SanitizedVarList()
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