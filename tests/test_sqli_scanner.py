import unittest
from unittest.mock import patch, Mock
from scanner.sqli.scanner import perform_sqli_scan
from scanner.sqli.errors import SQL_ERRORS

class TestSQLInjectionScanner(unittest.TestCase):

    @patch('requests.get')
    def test_sqli_scan_detection(self, mock_get):
        """Test that SQL Injection vulnerabilities are detected correctly."""
        
        # Sample URL to test
        target_url = "http://example.com/search"
        
        # Example payload for SQL injection
        payload = "' OR '1'='1"
        
        # Mocking the response for the injected URL
        mock_response = Mock()
        mock_response.text = "you have an error in your sql syntax;"  # Simulating SQL error
        mock_response.status_code = 200  # Ensure the mock returns a 200 OK status
        mock_get.return_value = mock_response  # Mock the requests.get call to return our mock response
        
        # Call the perform_sqli_scan function
        vulnerabilities = perform_sqli_scan(target_url, depth=1, verbose=False)
        
        # Check if vulnerabilities list is not empty
        self.assertGreater(len(vulnerabilities), 0, "No vulnerabilities found.")
        
        # Check if the detected vulnerability contains the correct payload and error
        vulnerability = vulnerabilities[0]
        self.assertEqual(vulnerability['payload'], payload, "Incorrect payload detected.")
        
        # Ensure the error pattern matches the mock response
        matched_error = False
        for error_pattern in SQL_ERRORS["MySQL"]:
            if error_pattern in mock_response.text.lower():
                matched_error = True
                break
        
        self.assertTrue(matched_error, "SQL error pattern not detected.")
    
    @patch('requests.get')
    def test_no_sqli_detected(self, mock_get):
        """Test that no SQL Injection vulnerabilities are detected when there are no errors."""
        
        # Sample URL to test
        target_url = "http://example.com/search"
        
        # Example payload for SQL injection
        payload = "' OR '1'='1"
        
        # Mocking the response for the injected URL without any SQL errors
        mock_response = Mock()
        mock_response.text = "Everything is fine"
        mock_response.status_code = 200  # Ensure the mock returns a 200 OK status
        mock_get.return_value = mock_response  # Mock the requests.get call to return our mock response
        
        # Call the perform_sqli_scan function
        vulnerabilities = perform_sqli_scan(target_url, depth=1, verbose=False)
        
        # Check if no vulnerabilities were detected
        self.assertEqual(len(vulnerabilities), 0, "Vulnerabilities incorrectly detected.")
    
if __name__ == '__main__':
    unittest.main()
