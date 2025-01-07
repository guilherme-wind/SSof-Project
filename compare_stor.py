import os
import json
import subprocess


def find_files(directory, extension):
    """Recursively find all files with the given extension in the directory."""
    files = []
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            if filename.endswith(extension):
                files.append(os.path.join(root, filename))
    return files


def load_json(file_path):
    """Load a JSON file and return its content."""
    with open(file_path, 'r') as f:
        return json.load(f)


def compare_outputs(expected_file, generated_file):
    """Compare expected and generated JSON files using validate.py."""
    try:
        result = subprocess.run(
            ['python3', 'validate.py', '-o', generated_file, '-t', expected_file],
            capture_output=True,
            text=True,
            check=True
        )
        print(result.stdout)
        print(result.stderr)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Error during validation: {e}")
        print(e.stdout)
        print(e.stderr)
        return False


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
    compare_directory = './compare'  # Directory to store comparison results

    if not os.path.exists(compare_directory):
        os.makedirs(compare_directory)

    comparison_results = []

    for js_folder in js_folders:
        js_files = find_files(js_folder, '.js')
        pattern_files = find_files(js_folder, 'patterns.json')

        for js_file in js_files:
            slice_name = os.path.basename(js_file).split('.')[0]
            for pattern_file in pattern_files:
                pattern_name = os.path.basename(pattern_file).split('.')[0]
                if slice_name == pattern_name:
                    expected_output_file = f"{js_folder}/{slice_name}.output.json"
                    generated_output_file = f"{output_directory}/{slice_name}.output.json"

                    result = {
                        "slice_name": slice_name,
                        "expected_output_file": expected_output_file,
                        "generated_output_file": generated_output_file,
                        "match": compare_outputs(expected_output_file, generated_output_file)
                    }

                    comparison_results.append(result)
                    break  # Break the loop once the match is found

    compare = subprocess.run(['python', 'compare_all.py'], capture_output=True, text=True)

if __name__ == "__main__":
    main()
