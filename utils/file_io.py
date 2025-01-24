### file_io.py

# Handles file I/O operations for saving results and logs
import os
import json

def save_results_to_json(results, output_path, verbose=False):
    try:
        with open(f"{output_path}.json", 'w') as json_file:
            json.dump(results, json_file, indent=4)
        if verbose:
            print(f"[INFO] JSON results saved to {output_path}.json")
    except Exception as e:
        raise RuntimeError(f"Failed to write JSON output: {e}")

def save_results_to_text(results, output_path, console_output, verbose=False):
    try:
        with open(f"{output_path}.txt", 'w') as txt_file:
            txt_file.write("Console Output:\n")
            txt_file.write(console_output)
            txt_file.write("\n\nResults Summary:\n")
            txt_file.write("-" * 20 + "\n")
            for key, value in results.items():
                txt_file.write(f"{key}: {value}\n")
        if verbose:
            print(f"[INFO] Plain text results saved to {output_path}.txt")
    except Exception as e:
        raise RuntimeError(f"Failed to write plain text output: {e}")

def ensure_output_dir(output_path):
    output_dir = os.path.dirname(output_path)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
