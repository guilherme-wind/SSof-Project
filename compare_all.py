import os
import json

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
    """Compare expected and generated JSON files."""
    expected_data = load_json(expected_file)
    generated_data = load_json(generated_file)

    # Compare the data
    return expected_data == generated_data

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

    # Save comparison results to a JSON file
    compare_file_path = f"{compare_directory}/comparison_results.json"
    with open(compare_file_path, 'w') as compare_file:
        json.dump(comparison_results, compare_file, indent=4)

    print(f"Comparison results saved to: {compare_file_path}")

if __name__ == "__main__":
    main()