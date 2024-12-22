import sys
import os
import json
import esprima
import logging
import argparse

def save(output_path, data):
    """
    Save data to the specified output path, ensuring it is saved inside an 'output' folder.
    """
    output_directory = os.path.join("output", os.path.dirname(output_path) or "")
    os.makedirs(output_directory, exist_ok=True)
    final_path = os.path.join("output", output_path)
    with open(final_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4)

    print(f"Results saved to: {final_path}")



# file_path: str = "./Examples/2-expr-binary-ops/2-expr-binary-ops.js"
file_path: str = "./wang_test.js"

try:
    with open(file_path, 'r', encoding='utf-8') as file:
        slice_code = file.read()
except Exception as e:
    logging.error(f"Failed to load file {file_path}: {e}")
    sys.exit(1)

parsed_ast = esprima.parseScript(slice_code, loc=False).toDict()

save("wang_testing.json", parsed_ast)