import unittest
from unittest.mock import patch, mock_open
from utils.file_io import save_results_to_json, save_results_to_text

class TestFileIO(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')  # Mock json.dump to prevent actual file writing
    def test_save_results_to_json(self, mock_json_dump, mock_file):
        """Test if the results are saved to a JSON file correctly."""
        
        # Sample data to write
        results = {
            "target_url": "http://example.com",
            "scan_type": "sqli",
            "depth": 1,
            "results": {
                "sqli": [
                    {"url": "http://example.com/search", "payload": "' OR '1'='1", "error": "you have an error in your sql syntax;"}
                ]
            }
        }
        output_path = 'outputs/results.json'  # Expected file path

        # Call the function to save the results
        save_results_to_json(results, output_path)

        # Check if the file was opened in write mode
        mock_file.assert_called_with(output_path, 'w')
        
        # Check if json.dump was called to save the results
        mock_json_dump.assert_called_once_with(results, mock_file.return_value, indent=4)

    @patch('builtins.open', new_callable=mock_open)
    def test_save_results_to_text(self, mock_file):
        """Test if the results are saved to a text file correctly."""
        
        # Sample data to write
        results = {
            "target_url": "http://example.com",
            "scan_type": "sqli",
            "depth": 1,
            "results": {
                "sqli": [
                    {"url": "http://example.com/search", "payload": "' OR '1'='1", "error": "you have an error in your sql syntax;"}
                ]
            }
        }
        console_output = "Results for SQL Injection scan"
        output_path = 'outputs/results.txt'  # Expected file path

        # Call the function to save the results
        save_results_to_text(results, output_path, console_output)

        # Check if the file was opened in write mode
        mock_file.assert_called_with(output_path, 'w')

        # Check if the correct content was written to the file
        mock_file.return_value.write.assert_any_call("Console Output:\n")
        mock_file.return_value.write.assert_any_call(console_output)
        mock_file.return_value.write.assert_any_call("\n\nResults Summary:\n")

        # Ensure the results summary was written
        self.assertIn("target_url", mock_file.return_value.write.call_args_list[2][0][0])

if __name__ == '__main__':
    unittest.main()
