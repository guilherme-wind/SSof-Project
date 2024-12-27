from enum import Enum
import esprima
from pygments.lexers.textfmts import TodotxtLexer

from js_analyser import vulnerabilities

sources = []
sinks = []
tainted_vars = []
vulnerabilities = []
stack = []


class PresentIn(Enum):
    SOURCES = 1,
    TAINTED = 2,
    SINKS = 3,
    NONE = 4,

class TaintedVar:
    def __init__(self, name):
        self.from_sources = set()
        self.name = name
    def add_source(self, source):
        self.from_sources.add(source)

def analyze(node):
    if 'Program' in node['type']:
        for stm in node['body']:
            statement(stm)
            return
    if 'Expression' or 'Literal' in node['type']:
        expression(node)
        return

def identifier(node):
    if node['name'] in sources:
        return PresentIn.SOURCES, node['name']
    elif node['name'] in tainted_vars:
        return PresentIn.TAINTED, node['name']
    elif node['name'] in sinks:
        return PresentIn.SINKS, node['name']

def statement(node):
    if node['type'] == 'ExpressionStament':
        expression(node['expression'])
    if node['type'] == 'BlockStatement':
        for statementNode in node['body']:
            statement(statementNode)
    if node['type'] == 'IfStatement':
        stack.append("If")
        expression(node['test'])
        statement(node['consequent'])
        if node['alternate'] is not None:
            statement(node)
    if node['type'] == 'WhileStatement' or 'DoWhileStatement':
        stack.append("While")
        expression(node.test)
        stack.pop()
    else:
        return

def declaration(node):
    if node['type'] == 'FunctionDeclaration':
        #TODO
        return
    if node['type'] == 'VariableDeclaration':
        for declarator in node['declarations']:
            expression(declarator['init'])

def expression(node):
    if node['type'] == 'UnaryExpression':
        expression(node['argument'])
    if node['type'] == 'BinaryExpression':
        return binary_expr(node)
    if node['type'] == 'AssignmentExpression':
        return assignment_expr(node)
    if node['type'] == 'LogicalExpression':
        expression(node['left'])
        expression(node['right'])
    if node['type'] == 'MemberExpression':
        expression(node['object'])
        expression(node['property'])
    if node['type'] == 'CallExpression':
        expression(node['callee'])
        for arg in node['argument']:
            expression(arg)
    else:
        return

def binary_expr(node):
    result_left = expression(node['left'])
    result_right = expression(node['right'])


def assignment_expr(node):
    #result of the left hand side
    result_right = None
    #result of the right hand side
    result_left = None

    if 'Expression' in node['left']['type'] :
        result_left = expression(node['left'])
    else:
        result_left = identifier(node['left'])
    
    result_right = expression(node['right'])

    if result_right['type'] == PresentIn.SOURCES or result_right['type'] == PresentIn.TAINTED:
        if result_left['type'] == PresentIn.SINK:
            #how to implment this part is yet to be discussed
            #vulnerabilities.add()
            return
    if result_left['type'] == PresentIn.NONE:
        tainted_var.add(result_left['name'])
    if result_left['type'] == PresentIn.TAINTED:
        already_tainted = tainted_var.get(result_left['name'])
        already_tainted.add_source(result_right)
        tainted_var.add(already_tainted)
        
