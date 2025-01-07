import os
import subprocess

def find_files(directory, extension):
    """Recursively find all files with the given extension in the directory."""
    files = []
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            if filename.endswith(extension):
                files.append(os.path.join(root, filename))
    return files

def main():
    base_directory = './examples'  # The directory containing the examples folders
    js_folders = [
        './examples/1-basic-flow',
        './examples/2-expr-binary-ops',
        './examples/3-expr',
        './examples/4-conds-branching',
        './examples/5-loops',
        './examples/6-sanitization',
        './examples/7-conds-implicit',
        './examples/8-loops-implicit',
        './examples/9-regions-guards'
    ]  # Folder names from 1 to 9
    output_directory = './output'

    for js_folder in js_folders:
        js_files = find_files(js_folder, '.js')
        pattern_files = find_files(js_folder, 'patterns.json')

        for js_file in js_files:
            slice_name = os.path.basename(js_file).split('.')[0]
            for pattern_file in pattern_files:
                pattern_name = os.path.basename(pattern_file).split('.')[0]
                if slice_name == pattern_name:
                    output_file = f"{output_directory}/{slice_name}.output.json"
                    print(f"Testing {js_file} with {pattern_file}")
                    result = subprocess.run(['python', 'better_call_chino.py', js_file, pattern_file], capture_output=True, text=True, timeout=10)
                    print(result.stdout)
                    print(result.stderr)
                    break  # Break the loop once the match is found
                
    compare = subprocess.run(['python', 'compare.py'], capture_output=True, text=True)

if __name__ == "__main__":
    main()
