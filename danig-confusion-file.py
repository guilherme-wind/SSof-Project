import json
import esprima
sources = ''
sinks = ''
sanitizers = ''

tainted_vars = {}
vulnerabilities = []
vulnerability_counter = 1

"!!!!!!!Copiado do js_analyzer!!!!!!!!! e do pseudocódigo (amálgama dos dois)"
def vulnerabilities(ast: dict, pattern: dict) -> list:
    sources = pattern["sources"]
    sinks = pattern["sinks"]
    sanitizers = pattern["sanitizers"]

    tainted_vars = {}
    vulnerabilities = []
    vulnerability_counter = 1

    def traverse(node, implicit_context=False):
        nonlocal vulnerability_counter

        if not isinstance(node, dict) or "type" not in node:
            return

        # Handle assignment expressions
        if 'Statement' in node['type']:
            statement(node)

        if 'Declaraction' in node['type']:
            declaration(node)

        if 'Expression' or 'Literal' or 'Identifier' in node['type'] :
            expression(node)

        if node["type"] == "AssignmentExpression":
            left = extract(node["left"])
            right = node["right"]

            # Taint propagation logic (order matters)
            if right["type"] == "Identifier":
                if right["name"] in tainted_vars:
                    tainted_vars[left] = tainted_vars[right["name"]]
                elif left in tainted_vars:
                    tainted_vars[right["name"]] = tainted_vars[left]
            elif right["type"] == "CallExpression" and extract(right["callee"]) in sources:
                tainted_vars[left] = {"source": extract(right["callee"]), "line": node["loc"]["start"]["line"]}
            elif right["type"] == "Literal" and right["value"] == "":
                tainted_vars.pop(left, None)  # Clear taint for empty values
            else:
                tainted_vars.pop(left, None)  # Clear taint if assigned a safe value

            # Sink detection in assignment
            if left in sinks and left in tainted_vars:
                sanitized_flow = collect_sanitizations(right, sanitizers)
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

        # Handle function call sinks
        if node["type"] == "CallExpression":
            function_name = extract(node["callee"])
            if function_name in sinks:
                for arg in node["arguments"]:
                    arg_name = extract(arg)
                    if arg_name in tainted_vars:
                        sanitized_flow = collect_sanitizations(arg, sanitizers)
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

        # Handle control flow structures for implicit taint tracking
        if node["type"] in ["IfStatement", "WhileStatement", "ForStatement", "SwitchStatement"]:
            if "consequent" in node:  # IfStatement
                traverse(node["consequent"], implicit_context=True)
            if "alternate" in node and node["alternate"]:  # IfStatement with else block
                traverse(node["alternate"], implicit_context=True)
            if "body" in node:  # Loops
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

def collect_sanitizations(node, sanitizers):
    sanitization_flow = []
    if node["type"] == "CallExpression":
        function_name = extract(node["callee"])
        if function_name in sanitizers:
            sanitization_flow.append([function_name, node["loc"]["start"]["line"]])
        for arg in node["arguments"]:
            sanitization_flow.extend(collect_sanitizations(arg, sanitizers))
    return sanitization_flow

def extract(node):
    if node["type"] == "Identifier":
        return node["name"]
    if node["type"] == "Literal":
        return node["value"]
    if node["type"] == "MemberExpression":
        object_name = extract(node["object"])
        property_name = extract(node["property"])
        return f"{object_name}.{property_name}"
    return ""

def statement(node):
    if node['type'] == 'ExpressionStament':
        expression(node)
    if node['type'] == 'BlockStatement':
    # I don't know how to traverse a block statement
    if node['type'] == 'IfStatement':
        expression(node.test)
        statement(node.consequent)
        if node.alternate is not None:
            statement(node.alternate)

def expression(node):
    if node['type'] == 'ThisExpression':
        return
    if node['type'] == 'ArrayExpression':
        for element in node['elements']:
            if element is None:
                continue
            expression(element)
    if node['type'] == 'ObjectExpression':
        return
    if node['type'] == 'FunctionExpression':
        return
    if node['type'] == 'UnaryExpression' or 'UpdateExpression':
        expression(node['arguments'])
    if node['type'] == 'BinaryExpression':
        expression(node['left'])
        expression(node['right'])
    if node['type'] == 'AssignmentExpression':
        ##TIRADO DO JS_ANALYZER
        left = extract(node["left"])
        right = node["right"]

        # Taint propagation logic (order matters)
        if right["type"] == "Identifier":
            if right["name"] in tainted_vars:
                tainted_vars[left] = tainted_vars[right["name"]]
            elif left in tainted_vars:
                tainted_vars[right["name"]] = tainted_vars[left]
        elif right["type"] == "CallExpression" and extract(right["callee"]) in sources:
            tainted_vars[left] = {"source": extract(right["callee"]), "line": node["loc"]["start"]["line"]}
        elif right["type"] == "Literal" and right["value"] == "":
            tainted_vars.pop(left, None)  # Clear taint for empty values
        else:
            tainted_vars.pop(left, None)  # Clear taint if assigned a safe value

        # Sink detection in assignment
        if left in sinks and left in tainted_vars:
            sanitized_flow = collect_sanitizations(right, sanitizers)
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
    if node['type'] == 'LogicalExpression':
        expression(node['left'])
        expression(node['right'])
    if node['type'] == 'MemberExpression':
        expression(node['object'])
        expression(node['property'])
    if node['type'] == 'CallExpression':
        expression(node['callee'])
        for arg in node['arguments']:
            expression(arg)

def declaration(node):
    if node['type'] == 'FunctionDeclaration':
        ##TODO
    if node['type'] == 'VariableDeclaration':
        for declarator in node['declarations']:
            expression(declarator['init'])

def main():
    ast_file = 'ast_danig_output.json'
    pattern_file = 'Examples/1-basic-flow/1a-basic-flow.patterns.json'

    ast = load_ast(ast_file)
    with open(pattern_file, 'r') as file:
        patterns = json.load(file)

    results = check_flows(ast, patterns)
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()