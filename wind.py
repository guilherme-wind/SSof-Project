import sys
import os
import json
import esprima
from enum import Enum
from typing import List, Any, Dict, Optional, Tuple, overload

results = []

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
        self.patterns: List[Pattern] = []
        for pattern in patterns:
            self.patterns.append(
                Pattern(
                    pattern["vulnerability"], 
                    pattern["sources"], 
                    pattern["sinks"],
                    pattern["sanitizers"]
                    )
                )
    
    def is_in_source(self, var: str) -> List[Pattern]:
        """
        Check if the variable is in the source of the patterns.
        Returns a list of pattern names where the variable is 
        present in the source.
        """
        results: List[Pattern] = []
        for pattern in self.patterns:
            if pattern.is_in_source(var):
                results.append(pattern)
        return results
    
    def is_in_sink(self, var: str) -> List[Pattern]:
        """
        Check if the variable is in the sink of the patterns.
        Returns a list of patterns where the variable is 
        present in the sink.
        """
        results: List[Pattern] = []
        for pattern in self.patterns:
            if pattern.is_in_sink(var):
                results.append(pattern)
        return results
    
    def is_in_sanitizer(self, var: str) -> List[Pattern]:
        """
        Check if the variable is in the sanitizer of the patterns.
        Returns a list of pattern names where the variable is 
        present in the sanitizer.
        """
        results: List[Pattern] = []
        for pattern in self.patterns:
            if pattern.is_in_sanitizer(var):
                results.append(pattern)
        return results
    
    def get_pattern(self, name: str) -> Pattern:
        for pattern in self.patterns:
            if pattern.get_name() == name:
                return pattern
        return None
# end class PatternList

class Taint:
    def __init__(self, source: str, line: int, pattern: Pattern, implicit: bool = False):
        self.source = source
        self.line = line
        self.pattern = pattern
        self.implicit = implicit
        self.sanitizer: List[Tuple[str, int]] = []

    def get_pattern(self) -> Pattern:
        return self.pattern
    
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
    
    def add_new_taint(self, source: str, line: int, pattern: Pattern, implicit: bool = False):
        """
        Add a new taint to the variable. Doesn't add the taint if it's already
        present in the variable.
        """
        if self.get_taint(source, line, pattern) is None:
            self.taint.append(Taint(source, line, pattern, implicit))
    
    def add_taint(self, taint: Taint):
        self.taint.append(taint)
    
    def merge_taints(self, taints: List[Taint]):
        """
        Merge a list of taints with the taints of the variable.
        """
        for taint in taints:
            if self.get_taint(taint.source, taint.line, taint.get_pattern()) is None:
                self.taint.append(taint)
    
    def get_taint(self, source: str, line: int, pattern: Pattern) -> Optional[Taint]:
        for taint in self.taint:
            if taint.source == source and taint.line == line and taint.pattern == pattern:
                return taint
        return None

    def get_all_taints(self) -> List[Taint]:
        return self.taint
    
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

def serialize_taint(taint: Taint) -> Dict:
    return {
        "source": taint.source,
        "line": taint.line,
        "pattern": taint.get_pattern().get_name(),
        "implicit": taint.implicit,
        "sanitizers": [{"name": san[0], "line": san[1]} for san in taint.sanitizer],
    }

def serialize_variable(variable: Variable) -> Dict:
    return {
        "name": variable.get_name(),
        "line": variable.initline,
        "taints": [serialize_taint(taint) for taint in variable.get_all_taints()],
    }


def list_merge(list1: list, list2: list) -> list:
    """
    Merges two lists into one, putting the elements of list2
    at the end of list1.
    """
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
        expression(node["test"], [])
        statement(node["consequent"])
        if "alternate" in node and node["alternate"] is not None:
            statement(node["alternate"])

    elif node["type"] == 'WhileStatement' or node["type"] == 'DoWhileStatement':
        expression(node["test"], [])
        statement(node["body"])


def expression(node: List[Dict[str, Any]], tainted: list) -> List[Variable]:
    if node["type"] == 'UnaryExpression':
        return expression(node["argument"], tainted) or []

    elif node["type"] == 'BinaryExpression':
        return binary_expr(node, tainted) or []
    
    elif node["type"] == 'AssignmentExpression':
        return assignment_expr(node, tainted) or []
    
    elif node["type"] == 'LogicalExpression':
        return []
    
    elif node["type"] == 'MemberExpression':
        return member_expr(node, tainted) or []
    
    elif node["type"] == 'CallExpression':
        return call_expr(node, tainted) or []
    
    elif node["type"] == 'Identifier':
        return identifier(node, tainted) or []
    
    elif node["type"] == 'Literal':
        return []
    
    return []

    
def identifier(node, tainted: list) -> List[Variable]:
    """
    Returns a variable object from the node.
    If the variable is not initialized, it will 
    have all the vulnerabilities.
    """
    # If the identifier is an initialized variable
    var = variablelist.is_in_variables(node['name'])
    if var != None:
        return [var]
    # If the identifier is a source
    var = patternlist.is_in_source(node['name'])
    if var != []:
        return [Variable(node['name'], 0)]
    # If the identifier is a sink
    var = patternlist.is_in_sink(node['name'])
    if var != []:
        return [Variable(node['name'], 0)]
    # If the identifier is a sanitizer
    var = patternlist.is_in_sanitizer(node['name'])
    if var != []:
        return [Variable(node['name'], 0)]
    # If the identifier is not initialized
    current_line = node['loc']['start']['line']
    var = Variable(node['name'], current_line)
    for pattern in patternlist.patterns:
        var.add_new_taint(node['name'], current_line, pattern)
    return [var]

def member_expr(node, taint: list) -> List[Variable]:
    """
    Converts a member expression to a list of variables.
    E.g.: a.b.c -> [a, b, c]
    """
    list: List[Variable] = []
    list_merge(list, expression(node['object'], []))
    list_merge(list, expression(node['property'], []))
    return list

def call_expr(node, taint: list) -> List[Variable]:
    """
    Evaluates a call expression and returns a single variable
    that combines the characteristics of the callee and the
    arguments.
    """
    
    global vulnerability_counter
    if 'vulnerability_counter' not in globals():
        vulnerability_counter = 1
    
    
    callee_name: List[Variable] = expression(node['callee'], [])
    arguments: List[Variable] = []
    for arg in node['arguments']:
        list_merge(arguments, expression(arg, []))

    current_line = node['loc']['start']['line']
    # Declare a variable that will collect all the taints
    # from the arguments and the callee
    return_variable: Variable = Variable("", current_line)

    for name in callee_name:
        # If the function is a sink
        sink_patterns = patternlist.is_in_sink(name.get_name())
        if sink_patterns != []:
            # Iterate over the arguments
            for arg in arguments:
                # If the argument is tainted
                for taint in arg.get_all_taints():
                    return_variable.add_new_taint(taint.source, taint.line, taint.get_pattern())
                    # If the pattern match the sink
                    if taint.get_pattern() in sink_patterns:
                        results.append({
                            "vulnerability": f"{taint.get_pattern().get_name()}_{vulnerability_counter}",
                            "source": [taint.source, taint.line],
                            "sink": [name.get_name(), current_line],
                            "unsanitized_flows": "yes" if not taint.sanitizer else "no",
                            "sanitized_flows": [{"name": san[0], "line": san[1]} for san in taint.sanitizer],
                            "implicit": "yes" if taint.implicit else "no",
                        })
                        vulnerability_counter += 1
                # If the argument is source
                source_patterns = patternlist.is_in_source(arg.get_name())
                for source in source_patterns:
                    return_variable.add_new_taint(arg.get_name(), current_line, source)
                    if source in sink_patterns:
                        results.append({
                            "vulnerability": f"{source.get_name()}_{vulnerability_counter}",
                            "source": [arg.get_name(), current_line],
                            "sink": [name.get_name(), current_line]
                        })
                        vulnerability_counter += 1

        # If the function is a sanitizer
        sanitizer_patterns = patternlist.is_in_sanitizer(name.get_name())
        if sanitizer_patterns != []:
            # Iterate over the arguments
            for arg in arguments:
                for taint in arg.get_all_taints():
                    # If the taint is already in the return variable
                    add_taint = return_variable.get_taint(taint.source, taint.line, taint.get_pattern())
                    if add_taint is None:
                        add_taint = Taint(taint.source, taint.line, taint.get_pattern())
                        return_variable.add_taint(add_taint)
                    # If the taint pattern is in the sanitizer patterns
                    if taint.get_pattern() in sanitizer_patterns:
                        add_taint.add_sanitizer((name, current_line))
        
        # If the function is a source
        source_patterns = patternlist.is_in_source(name.get_name())
        if source_patterns != []:
            # Add the taints of the arguments
            for arg in arguments:
                for taint in arg.get_all_taints():
                    return_variable.add_new_taint(taint.source, taint.line, taint.get_pattern())
            # Add the source pattern
            for source in source_patterns:
                return_variable.add_new_taint(name.get_name(), current_line, source)
            
    
    return [return_variable]


def assignment_expr(node, taint: list) -> List[Variable]:
    """
    Evaluates an assignment expresstion and returns a 
    single variable that combines the characteristics
    of the left and right side.
    """
    # list of variables on the left side
    result_left: List[Variable] = expression(node['left'], [])

    # list of variables on the right side
    result_right: List[Variable] = expression(node['right'], [])

    current_line = node['loc']['start']['line']
    
    global vulnerability_counter
    if 'vulnerability_counter' not in globals():
        vulnerability_counter = 1
    
    for left in result_left:
        # If the left side is a sink
        sink_patterns = patternlist.is_in_sink(left.get_name())
        if sink_patterns != []:
            # Iterate over the right side
            for right in result_right:
                # If the right side is tainted
                for taint in right.get_all_taints():
                    # return_variable.add_new_taint(taint.source, taint.line, taint.get_pattern())
                    if taint.get_pattern() in sink_patterns:
                        results.append({
                            "vulnerability": f"{taint.get_pattern().get_name()}_{vulnerability_counter}",
                            "source": [taint.source, taint.line],
                            "sink": [left.get_name(), current_line],
                            "unsanitized_flows": "yes" if not taint.sanitizer else "no",
                            "sanitized_flows": [{"name": san[0], "line": san[1]} for san in taint.sanitizer],
                            "implicit": "yes" if taint.implicit else "no",
                        })
                        vulnerability_counter += 1
                # If the right side is a source
                source_patterns = patternlist.is_in_source(right.get_name())
                for source in source_patterns:
                    # return_variable.add_new_taint(right.get_name(), current_line, source)
                    if source in sink_patterns:
                        results.append({
                            "vulnerability": f"{source.get_name()}_{vulnerability_counter}",
                            "source": [right.get_name(), current_line],
                            "sink": [left.get_name(), current_line],
                            "unsanitized_flows": "yes",
                            "sanitized_flows": [],
                            "implicit": "no"
                        })
                        vulnerability_counter += 1
        
        # If the left side is an initialized variable
        # TODO: optimize this part
        if variablelist.is_in_variables(left.get_name()) != None:
            
            # Merge with the taints of the right side
            for right in result_right:
                left.merge_taints(right.get_all_taints())
            # If the right side is a source, create new taints
            for right in result_right:
                left.merge_taints([
                    Taint(right.get_name(), current_line, pattern) 
                    for pattern in patternlist.is_in_source(right.get_name())
                ])

        # If the left side is an uninitialized variable
        elif left == result_left[-1]:
            # Initialize a new variable ONLY if its the last element
            # of the left side

            new_var = Variable(left.get_name(), current_line)

            # Merge with the taints of the right side
            for right in result_right:
                new_var.merge_taints(right.get_all_taints())

            # If the right side is a source, create new taints
            for right in result_right:
                new_var.merge_taints([
                    Taint(right.get_name(), current_line, pattern) 
                    for pattern in patternlist.is_in_source(right.get_name())
                ])
            
            variablelist.add_variable(new_var)
            
    return []


def binary_expr(node, taint: list) -> List[Variable]:


    pass
#     list = []
#     right_side = node['right']
#     left_side = node['left']

#     #It's not considering that it can be tainted sources, but I don't know how you want to do that
#     if tainted_vars.is_in_tainted_vars(right_side):
#         list.append(expression(right_side))
#     return list



























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

patternlist: PatternList
variablelist: VariableList = VariableList()
vulnerabilities: List[str] = []


def serialize_results(results):
        """
        Serializes the results list to ensure all objects are JSON-compatible.
        """
        serialized = []
        for result in results:
            if isinstance(result, Variable):
                serialized.append(serialize_variable(result))
            elif isinstance(result, dict):  # Already a dictionary
                serialized.append(result)
            else:
                raise TypeError(f"Cannot serialize object of type {type(result)}")
        return serialized

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
    global patternlist 
    patternlist = PatternList(raw_patterns)

    analyze(parsed_ast)

    # Serialize results
    serialized_results = serialize_results(results)
    
    # Print detected vulnerabilities
    print(f"\033[34mDetected Vulnerabilities:\033[0m\n{json.dumps(serialized_results, indent=4)}")

    # Save to output file
    output_file = f"{FileHandler.extract_filename_without_extension(slice_path)}.output.json"
    FileHandler.save(output_file, serialized_results)

if __name__ == "__main__":
    main()