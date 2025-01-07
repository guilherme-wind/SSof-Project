import copy
import sys
import os
import json
import esprima
from typing import List, Any, Dict, Optional, Tuple


class Pattern:
    def __init__(self, name: str, source: List[str], sink: List[str], sanitizer: List[str], implicit: str):
        self.name = name
        self.source = source
        self.sink = sink
        self.sanitizer = sanitizer
        self.implicit = False if implicit == "no" else True

    def __str__(self):
        return f"Vulnerability: {self.name}\nSource: {self.source}\nSink: {self.sink}\n"
    
    def __eq__(self, value):
        if not isinstance(value, Pattern):
            return False
        return self.name == value.name

    def __hash__(self):
        return hash(self.name)
    
    def get_name(self) -> str:
        return self.name
    
    def get_source(self) -> list:
        return self.source
    
    def get_sink(self) -> list:
        return self.sink
    
    def is_implicit(self) -> bool:
        return self.implicit
    
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
                    pattern["sanitizers"],
                    pattern["implicit"]
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
    
    def is_implicit(self) -> List[Pattern]:
        """
        Returns a list of patterns that are implicit.
        """
        results: List[Pattern] = []
        for pattern in self.patterns:
            if pattern.is_implicit():
                results.append(pattern)
        return results
    
    def get_pattern(self, name: str) -> Pattern:
        for pattern in self.patterns:
            if pattern.get_name() == name:
                return pattern
        return None
# end class PatternList

class TaintBranch:
    def __init__(self, implicit: bool = False):
        self.sanitizers: List[Tuple[str, int]] = []
        self.implicit = implicit
        self.unsanitized: bool = True
    
    def __eq__(self, value):
        if not isinstance(value, TaintBranch):
            return False
        return self.sanitizers == value.sanitizers

    def __str__(self):
        string = "["
        for san in self.sanitizers:
            string += f"[{san[0]}, {san[1]}], "
        return string + "]"
    
    def add_sanitizer(self, sanitizer: Tuple[str, int]):
        self.unsanitized = False
        if sanitizer not in self.sanitizers:
            self.sanitizers.append(sanitizer)
    
    def add_sanitizers(self, sanitizers: List[Tuple[str, int]]):
        for sanitizer in sanitizers:
            self.add_sanitizer(sanitizer)
    
    def get_sanitizers(self) -> List[Tuple[str, int]]:
        return self.sanitizers
    
    def is_unsanitized(self) -> bool:
        return self.unsanitized
    
    def copy(self) -> 'TaintBranch':
        """
        Returns a deep copy of the TaintBranch object.
        """
        copy = TaintBranch(self.implicit)
        for sanitizer in self.sanitizers:
            copy.add_sanitizer(sanitizer)
        return copy
# end class TaintBranch

class Taint:
    def __init__(self, source: str, line: int, pattern: Pattern, implicit: bool = False):
        self.source = source
        self.line = line
        self.pattern = pattern
        self.implicit = implicit
        self.branches: List[TaintBranch] = []
    
    def __str__(self):
        vulnerability = self.pattern.get_name()
        source = self.source
        line = self.line
        unsanitized_flows: str = "yes"
        sanitized_flows: str = ""
        for branch in self.branches:
            if not branch.is_unsanitized():
                unsanitized_flows = "no"
            sanitized_flows += f"{branch}, "
        return f"Vulnerability: {vulnerability}, Source: [{source}, {line}], Unsanitized flows: {unsanitized_flows}"
    
    def __eq__(self, value):
        if not isinstance(value, Taint):
            return False
        return self.source == value.source and self.line == value.line and self.pattern == value.pattern

    def __hash__(self):
        return hash((self.source, self.line, self.pattern))

    def get_pattern(self) -> Pattern:
        return self.pattern
    
    def get_branches(self) -> List[TaintBranch]:
        return self.branches
    
    def add_branch(self, branch: TaintBranch):
        self.branches.append(branch)
    
    def add_new_branch(self):
        """
        Create a new branch without any sanitizer.
        """
        new_branch = TaintBranch()
        self.branches.append(new_branch)
    
    def add_new_branch_sanitizers(self, sanitizers: List[Tuple[str, int]]):
        """
        Add a new branch to the taint with a list of sanitizers.
        """
        new_branch = TaintBranch()
        new_branch.add_sanitizers(sanitizers)
        self.branches.append(new_branch)
    
    def add_sanitizer_all_branches(self, sanitizer: Tuple[str, int]):
        """
        Add a sanitizer to all the branches of the taint.
        """
        for branch in self.branches:
            branch.add_sanitizer(sanitizer)
    
    def add_sanitizer(self, sanitizer: Tuple[str, int]):
        """
        deprecated
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
        for branch in self.branches:
            copy.add_branch(branch.copy())
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
        """
        Add a taint to the variable. Makes a copy of the taint added.
        """
        self.taint.append(taint.copy())
    
    def merge_taints(self, taints: List[Taint]):
        """
        Merge a list of taints with the taints of the variable.
        This method makes a copy of the taints added to the variable.
        """
        for taint in taints:
            existing_taint = self.get_taint(taint.source, taint.line, taint.get_pattern())
            if existing_taint is None:
                self.taint.append(taint.copy())
            else:
                # Compare the branches of the taints
                for branch in taint.get_branches():
                    existing_branch = existing_taint.get_branches()
                    if existing_branch is [] or branch != existing_branch:
                        existing_taint.add_branch(branch.copy())
    
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

class Vulnerability:
    def __init__(self, taint: Taint, counter: int, sink: str, line: int, implicit: bool):
        self.counter = counter
        self.taint = taint
        self.sink = sink
        self.line = line
        self.implicit = implicit

    def __eq__(self, value):
        if not isinstance(value, Vulnerability):
            return False
        return self.taint == value.taint and self.sink == value.sink and self.line == value.line
    
    def to_json(self) -> Dict[str, Any]:
        vuln_name = self.taint.get_pattern().get_name() + "_" + str(self.counter)
        is_unsanitized: bool = False
        branches: list = []
        taint_branches = self.taint.get_branches()
        # If there are no branches
        if taint_branches == []:
            is_unsanitized = True
        for branch in self.taint.get_branches():
            sanitizer = branch.get_sanitizers()
            # If there are sanitizers
            if sanitizer != []:
                branches.append(sanitizer)
            else:
                is_unsanitized = True
        return {
            "vulnerability": vuln_name,
            "source": [self.taint.source, self.taint.line],
            "sink": [self.sink, self.line],
            "unsanitized_flows": "yes" if is_unsanitized else "no",
            "sanitized_flows": branches,
            "implicit": "yes" if self.implicit else "no"
        }
# end class Vulnerability

class VulnerabilityList:
    def __init__(self):
        self.vulnerabilities: Dict[Taint, List[Vulnerability]] = dict()
        self.counters: Dict[Pattern, int] = dict()
    
    def add_vulnerability(self, taint: Taint, sink: str, line: int, implicit: bool = False):
        # If the vulnerability with such pattern doesn't exist yet
        if taint.get_pattern() not in self.counters:
            self.counters[taint.get_pattern()] = 1
            self.vulnerabilities[taint] = [
                Vulnerability(
                    taint, 
                    self.counters[taint.get_pattern()], 
                    sink, 
                    line, 
                    implicit
                )
            ]
            return
        
        # If the vulnerability with such pattern exists
        # Check if the vulnerability with the same taint exists
        if taint not in self.vulnerabilities:
            self.counters[taint.get_pattern()] += 1
            self.vulnerabilities[taint] = [
                Vulnerability(
                    taint, 
                    self.counters[taint.get_pattern()], 
                    sink, 
                    line, 
                    implicit
                )
            ]
            return

        vulnerabilities = self.vulnerabilities[taint]
        for vuln in vulnerabilities:
            if vuln.sink == sink and vuln.line == line:
                return

        self.counters[taint.get_pattern()] += 1
        vulnerabilities.append(
            Vulnerability(
                taint, 
                self.counters[taint.get_pattern()], 
                sink, 
                line, 
                implicit
            )
        )
    
    def to_json(self) -> List[Dict[str, Any]]:
        result = []
        for vuln_list in self.vulnerabilities.values():
            for vuln in vuln_list:
                result.append(vuln.to_json())
        return result
# end class VulnerabilityList

class Branch:
    """
    Represents a branch in the code, i.e., a possible path that the code
    can take.
    """
    def __init__(self, initialized_vars: VariableList, guard_taints: List[Taint], is_implicit: bool):
        self.initialized_vars = initialized_vars
        self.guard_taints = guard_taints
        self.is_implicit = is_implicit

    def add_initialized_variable(self, variable: Variable):
        self.initialized_vars.add_variable(variable)

    def add_guard_taint(self, taint: Taint):
        add_taint_to_list(taint, self.guard_taints)

    def get_initialized_variables(self) -> VariableList:
        return self.initialized_vars

    def get_guard_taints(self) -> List[Taint]:
        return self.guard_taints

    def get_is_implicit(self) -> bool:
        return self.is_implicit

    def set_implicit(self, is_implicit: bool):
        self.is_implicit = is_implicit

    def merge_branches(self, branches: List['Branch']):
        for branch in branches:
            # Merge initialized variables
            for variable in branch.get_initialized_variables().variables:
                existing_variable = self.initialized_vars.is_in_variables(variable.get_name())
                if existing_variable is None:
                    self.initialized_vars.add_variable(variable.copy())
                else:
                    # Merge taints if the variable already exists
                    existing_variable.merge_taints(variable.get_all_taints())

            # Merge guard taints
            for taint in branch.get_guard_taints():
                add_taint_to_list(taint, self.guard_taints)
                # if taint not in self.guard_taints:
                #     self.guard_taints.append(taint)

            # Update implicit property if any branch is implicit
            if branch.get_is_implicit():
                self.is_implicit = True
# end class Branch

# ========================= Utility functions =========================
def list_copy(list: list) -> list:
    """
    Returns a deep copy of a list.
    """
    return list[:]

def list_merge(list1: list, list2: list) -> list:
    """
    Merges two lists into one, putting the elements of list2
    at the end of list1.
    """
    for element in list2:
        list1.append(element)
    return list1

def taints_in_patterns(taints: List[Taint], patterns: List[Pattern]) -> List[Taint]:
    """
    Returns a list of taints that are in the patterns.
    """
    results: List[Taint] = []
    for taint in taints:
        if taint.get_pattern() in patterns:
            results.append(taint)
    return results

def taints_not_in_patterns(taints: List[Taint], patterns: List[Pattern]) -> List[Taint]:
    """
    Returns a list of taints that are not in the patterns.
    """
    results: List[Taint] = []
    for taint in taints:
        if taint.get_pattern() not in patterns:
            results.append(taint)
    return results

def add_taint_to_list(to_add_taint: Taint, taints: List[Taint]):
    """
    Adds a taint to a list of taints. If the taint is already
    present in the list, their branches will be merged.
    """
    if to_add_taint not in taints:
        taints.append(to_add_taint)
    
    for t in taints:
        if t == to_add_taint:
            for branch in to_add_taint.get_branches():
                if t.get_branches() == [] or branch not in t.get_branches():
                    t.add_branch(branch)

def merge_taint_lists(list1: List[Taint], list_to_be_merged: List[Taint]):
    """
    Merges two lists of taints into one. If a taint is present
    in both lists, their branches will be merged.
    """
    for taint in list_to_be_merged:
        add_taint_to_list(taint, list1)
# =====================================================================


def analyze(node):
    if not isinstance(node, dict) or "type" not in node:
        return
    
    initial_context = Branch(VariableList(), [], False)
    contexts = [initial_context]
    aux_list = []
    
    if node["type"] == 'Program':
        for child in node["body"]:
            for context in contexts:
                list_merge(aux_list, statement(child, context))
            contexts = aux_list
            aux_list = []

    return


def statement(node: List[Dict[str, Any]], context: Branch) -> List[Branch]:
    if node["type"] == 'ExpressionStatement':
        expression(node["expression"], context)
        return [context]

    elif node["type"] == 'BlockStatement':
        result = []
        for child in node["body"]:
            list_merge(result, statement(child, context))
        return result

    elif node["type"] == 'IfStatement':
        return if_statem(node, context)

    elif node["type"] == 'WhileStatement' | node["type"] == 'DoWhileStatement':
        expression(node["test"], context)
        statement(node["body"], context)
        return []

    else:
        return []



def expression(node: List[Dict[str, Any]], context: Branch) -> List[Variable]:
    if node["type"] == 'UnaryExpression':
        return expression(node["argument"], context)

    elif node["type"] == 'BinaryExpression':
        return binary_expr(node, context)
    
    elif node["type"] == 'AssignmentExpression':
        return assignment_expr(node, context)
    
    elif node["type"] == 'LogicalExpression':
        return logical_expr(node, context)
    
    elif node["type"] == 'MemberExpression':
        return member_expr(node, context)
    
    elif node["type"] == 'CallExpression':
        return call_expr(node, context)
    
    elif node["type"] == 'Identifier':
        return identifier(node, context)
    
    elif node["type"] == 'Literal':
        return []
    
    else:
        return
    
def identifier(node, context: Branch) -> List[Variable]:
    """
    Returns a variable object from the node.
    If the variable is not initialized, it will 
    have all the vulnerabilities.
    """
    # If the identifier is an initialized variable
    var = context.initialized_vars.is_in_variables(node['name'])
    if var != None:
        return [var]
    # If the identifier is not initialized
    current_line = node['loc']['start']['line']
    var = Variable(node['name'], current_line)
    for pattern in patternlist.patterns:
        taint = Taint(node['name'], current_line, pattern)
        taint.add_new_branch()
        var.add_taint(taint)
    return [var]

def member_expr(node, context: Branch) -> List[Variable]:
    """
    Converts a member expression to a list of variables.
    E.g.: a.b.c -> [a, b, c]
    """
    list: List[Variable] = copy.deepcopy(expression(node['object'], context))
    list_merge(list, expression(node['property'], context))
    return list

def call_expr(node, context: Branch) -> List[Variable]:
    """
    Evaluates a call expression and returns a single variable
    that combines the characteristics of the callee and the
    arguments.
    """
    callees: List[Variable] = copy.deepcopy(expression(node['callee'], context))
    arguments: List[Variable] = []
    for arg in node['arguments']:
        list_merge(arguments, copy.deepcopy(expression(arg, context)))

    current_line = node['loc']['start']['line']
    # Declare a variable that will collect all the taints
    # from the arguments and the callee
    return_variable: Variable = Variable("", current_line)
    aux_taint_list: List[Taint] = []
    
    # Add all existing taints and new taints to the list
    for arg in arguments:
        merge_taint_lists(aux_taint_list, arg.get_all_taints())
        # If the argument is a source
        source_patterns = patternlist.is_in_source(arg.get_name())
        for source in source_patterns:
            # Create new taint
            new_taint = Taint(arg.get_name(), current_line, source)
            new_taint.add_new_branch()
            add_taint_to_list(new_taint, aux_taint_list)
    

    for callee in callees:
        # If the function is a sink
        sink_patterns = patternlist.is_in_sink(callee.get_name())
        if sink_patterns != []:
            # Filter the taints that can fall into the sink
            sinkable_taints = taints_in_patterns(aux_taint_list, sink_patterns)
            for taint in sinkable_taints:
                # Register the vulnerability
                vulnerabilities.add_vulnerability(taint, callee.get_name(), current_line)
                print({
                    "vulnerability": taint.get_pattern().get_name(),
                    "source": [taint.source, taint.line],
                    "sink": [callee.get_name(), current_line],
                    "sanitized_flows": [branch.get_sanitizers() for branch in taint.get_branches()]
                })

        # If the function is a sanitizer
        sanitizer_patterns = patternlist.is_in_sanitizer(callee.get_name())
        if sanitizer_patterns != []:
            # Filter the taints that can be sanitized
            sanitizable_taints = taints_in_patterns(aux_taint_list, sanitizer_patterns)
            for taint in sanitizable_taints:
                # Add the saniziter
                taint.add_sanitizer_all_branches((callee.get_name(), current_line))

        # If the function is a source
        source_patterns = patternlist.is_in_source(callee.get_name())
        if source_patterns != []:
            for source in source_patterns:
                new_taint = Taint(callee.get_name(), current_line, source)
                new_taint.add_new_branch()
                add_taint_to_list(new_taint, aux_taint_list)
        
        # If the callee is not the last element of the callees
        # which means that it's not the function, but instead
        # the object that contains the function
        if callee != callees[-1]:
            # Merge the taints of the callee
            list_merge(aux_taint_list, callee.get_all_taints())

    return_variable.merge_taints(aux_taint_list)
    
    return [return_variable]


def assignment_expr(node, context: Branch) -> List[Variable]:
    """
    Evaluates an assignment expresstion and returns a 
    single variable that combines the characteristics
    of the left and right side.
    """
    # list of variables on the left side
    result_left: List[Variable] = copy.deepcopy(expression(node['left'], context))

    # list of variables on the right side
    result_right: List[Variable] = copy.deepcopy(expression(node['right'], context))

    current_line = node['loc']['start']['line']

    return_variable: Variable = Variable("", current_line)
    right_taint_list: List[Taint] = []
    left_taint_list: List[Taint] = []

    for right in result_right:
        # If the right side is tainted
        list_merge(right_taint_list, right.get_all_taints())
        # If the right side is a source
        source_patterns = patternlist.is_in_source(right.get_name())
        for source in source_patterns:
            # Create new taint
            new_taint = Taint(right.get_name(), current_line, source)
            new_taint.add_new_branch()
            add_taint_to_list(new_taint, right_taint_list)

    for left in result_left:
        # If the left side is a sink
        sink_patterns = patternlist.is_in_sink(left.get_name())
        if sink_patterns != []:
            # Filter the taints that can fall into the sink
            sinkable_taints = taints_in_patterns(right_taint_list, sink_patterns)
            for taint in sinkable_taints:
                vulnerabilities.add_vulnerability(taint, left.get_name(), current_line)
                print({
                    "vulnerability": taint.get_pattern().get_name(),
                    "source": [taint.source, taint.line],
                    "sink": [left.get_name(), current_line],
                    "sanitized_flows": [branch.get_sanitizers() for branch in taint.get_branches()]
                })
        
        # If the left side is an initialized variable
        initialized_var = context.initialized_vars.is_in_variables(left.get_name())
        if initialized_var != None:
            # Merge with the taints of the right side
            left_taint_list = copy.deepcopy(initialized_var.get_all_taints())
            list_merge(left_taint_list, right_taint_list)
            initialized_var.merge_taints(right_taint_list)

        elif left == result_left[-1]:
            # Initialize a new variable ONLY if its the last element
            # of the left side
            left_taint_list = right_taint_list
            initialized_var = Variable(left.get_name(), current_line)
            initialized_var.merge_taints(right_taint_list)
            context.initialized_vars.add_variable(initialized_var)

    return_variable.merge_taints(left_taint_list)

    return [return_variable]


def binary_expr(node, context: Branch) -> List[Variable]:
    """
    Evaluates a binary expression and return a single variable
    that combines all the taints from the left and right side.
    """
    result_left = copy.deepcopy(expression(node['left'], context))
    result_right = copy.deepcopy(expression(node['right'], context))
    
    current_line = node['loc']['start']['line']

    return_variable: Variable = Variable("", current_line)
    aux_taint_list: List[Taint] = []

    for left in result_left:
        # If the left side is tainted
        list_merge(aux_taint_list, left.get_all_taints())
        # If the left side is a source
        source_patterns = patternlist.is_in_source(left.get_name())
        for source in source_patterns:
            new_taint = Taint(left.get_name(), current_line, source)
            new_taint.add_new_branch()
            add_taint_to_list(new_taint, aux_taint_list)
    
    for right in result_right:
        list_merge(aux_taint_list, right.get_all_taints())
        source_patterns = patternlist.is_in_source(right.get_name())
        for source in source_patterns:
            new_taint = Taint(right.get_name(), current_line, source)
            new_taint.add_new_branch()
            add_taint_to_list(new_taint, aux_taint_list)
    
    return_variable.merge_taints(aux_taint_list)
 
    return [return_variable]


def logical_expr(node, context: Branch) -> List[Variable]:
    """
    Evaluates a logical expression and returns a single variable
    that combines the taints of the left and right side.
    """
    return binary_expr(node, context)


def if_statem(node, context: Branch):

    # Analyze the test condition and obtain the taints
    guard_var = expression(node["test"], context)

    # Create a copy of current context for the consequent branch
    consequent_context = copy.deepcopy(context)
    for var in guard_var:
        for taint in var.get_all_taints():
            consequent_context.add_guard_taint(copy.deepcopy(taint))
    
    consequent_branches = statement(node["consequent"], consequent_context)

    # If there is no 'else' branch
    if "alternate" not in node:
        # The original branch is the 'else'
        consequent_branches.insert(0, context)
        return consequent_branches
    
    # Create a copy of current context for the alternate branch
    alternate_context = copy.deepcopy(context)
    for var in guard_var:
        for taint in var.get_all_taints():
            alternate_context.add_guard_taint(copy.deepcopy(taint))

    alternate_branches = statement(node["alternate"], alternate_context)

    # Merge the branches
    list_merge(consequent_branches, alternate_branches)

    return consequent_branches


















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
vulnerabilities: VulnerabilityList = VulnerabilityList()

def main():
    # slice_path = "./Examples/1-basic-flow/1b-basic-flow.js"
    # patterns_path = "./Examples/1-basic-flow/1b-basic-flow.patterns.json"
    # slice_path = "./Examples/2-expr-binary-ops/2-expr-binary-ops.js"
    # patterns_path = "./Examples/2-expr-binary-ops/2-expr-binary-ops.patterns.json"
    # slice_path = "./Examples/3-expr/3a-expr-func-calls.js"
    # patterns_path = "./Examples/3-expr/3a-expr-func-calls.patterns.json"
    # slice_path = "./Examples/4-conds-branching/4a-conds-branching.js"
    # patterns_path = "./Examples/4-conds-branching/4a-conds-branching.patterns.json"

    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]
    
    print(f"Analyzing slice: {slice_path}\nUsing patterns: {patterns_path}\n")

    slice_code: str = FileHandler.load_file(slice_path)
    raw_patterns: str = json.loads(FileHandler.load_file(patterns_path))

    parsed_ast = esprima.parseScript(slice_code, loc=True).toDict()
    global patternlist 
    patternlist = PatternList(raw_patterns)

    analyze(parsed_ast)

    output_file = f"{FileHandler.extract_filename_without_extension(slice_path)}.output.json"
    FileHandler.save(output_file, vulnerabilities.to_json())

if __name__ == "__main__":
    main()