import os
import json

def ensure_output_dir(output_path):
    """Ensure that the output directory exists, create it if necessary."""
    directory = os.path.dirname(output_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"[INFO] Created directory: {directory}")

def save_results_to_json(results, output_path, verbose=False):
    """Save results to a JSON file."""
    ensure_output_dir(output_path)
    
    if not output_path.endswith('.json'):
        output_path += '.json'

    try:
        with open(output_path, 'w') as json_file:
            json.dump(results, json_file, indent=4)
        if verbose:
            print(f"[INFO] JSON results saved to {output_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to write JSON output: {e}")

def save_results_to_text(results, output_path, console_output, verbose=False):
    """Save results to a text file."""
    ensure_output_dir(output_path)

    if not output_path.endswith('.txt'):
        output_path += '.txt'

    try:
        with open(output_path, 'w') as txt_file:
            txt_file.write("Console Output:\n")
            txt_file.write(console_output)
            txt_file.write("\n\nResults Summary:\n")
            txt_file.write("-" * 20 + "\n")
            for key, value in results.items():
                txt_file.write(f"{key}: {value}\n")
        if verbose:
            print(f"[INFO] Text results saved to {output_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to write text output: {e}")
