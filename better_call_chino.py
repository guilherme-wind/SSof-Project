import sys
import os
import json
import esprima
from typing import List, Any, Dict

vulnerabilities = []
tainted_vars = []



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

    slice_code = FileHandler.load_file(slice_path)
    patterns = json.loads(FileHandler.load_file(patterns_path))


    
    results = analyze(slice_code)

    print(f"\033[34mDetected Vulnerabilities:\033[0m\n{json.dumps(results, indent=4)}")

    output_file = f"{FileHandler.extract_filename_without_extension(slice_path)}.output.json"
    FileHandler.save(output_file, results)

if __name__ == "__main__":
    main()