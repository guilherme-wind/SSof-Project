import os, sys, json

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

class TaintedVar:
    def __init__(self, name):
        self.name = name
        self.sources = set()

    def add_source(self, source, line):
        self.sources.add((source, line))

    def get_sources(self):
        return self.sources
    

def expression(node):
    return {"name": node["name"], "type": node["type"]}


def identifier(node):
    return {"name": node["name"], "type": node.get("type", "NONE")}


def assignment_expr(node, tainted_vars, vulnerabilities):
    result_left = None
    result_right = None

    if 'Expression' in node['left']['type']:
        result_left = expression(node['left'])
    else:
        result_left = identifier(node['left'])
    result_right = expression(node['right'])

    # Constants for types (add real implementations later)
    SOURCES = "SOURCES"
    TAINTED = "TAINTED"
    SINK = "SINK"
    NONE = "NONE"

    if result_right['type'] in [SOURCES, TAINTED]:
        # If the left-hand side is a sink, register the vulnerability
        if result_left['type'] == SINK:
            vulnerabilities.append({
                "sink": result_left["name"],
                "source": result_right["name"]
            })
            return

        # If the left-hand side is a clean variable, it becomes tainted
        if result_left['type'] == NONE:
            tainted_vars[result_left['name']] = {
                "sources": {result_right["name"]}
            }

        # If the left-hand side is already tainted, update its sources
        elif result_left['type'] == TAINTED:
            already_tainted = tainted_vars[result_left['name']]
            already_tainted["sources"].add(result_right["name"])
            tainted_vars[result_left['name']] = already_tainted
    

def main():
    tainted_vars = []  
    var1 = TaintedVar("a")
    var1.add_source("b", 2)
    tainted_vars.append(var1)

    for var in tainted_vars:
        print(f"Variable: {var.name}, Sources: {var.get_sources()}")

if __name__ == "__main__":
    main()