import sys
import os
import json
import esprima

def load_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()
    
def main():
    if len(sys.argv) != 3:
        print("\033[31mError: Incorrect number of arguments.\033[0m")
        print("Example of how to call the program:")
        print("\033[32mUsage: python ./js_analyser.py <path_to_slice>/<slice>.js <path_to_pattern>/<patterns>.json\033[0m\n")
        sys.exit(1)

    # Decouple input arguments into variables
    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]
    slice_name = os.path.basename(slice_path).rsplit('.', 1)[0]
    output_file = f"./output/{slice_name}.output.json"

    # Load files
    slice_content = load_file(slice_path)
    patterns = json.loads(load_file(patterns_path))

if __name__ == "__main__":
    main()