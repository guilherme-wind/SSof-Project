from enum import Enum
import esprima

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
    if node['name'] in tainted_vars:
        return PresentIn.TAINTED, node['name']
    if node['name'] in sinks:
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
        if(node['alternate'] )