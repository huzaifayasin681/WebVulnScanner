import unittest
from bs4 import BeautifulSoup
from scanner.sqli.forms import extract_forms

class TestFormExtraction(unittest.TestCase):
    
    def test_extract_forms(self):
        """Test if the extract_forms function correctly extracts form details."""
        
        # Sample HTML for testing
        html_content = """
        <html>
            <body>
                <form action="/submit" method="POST">
                    <input type="text" name="username" value="testuser">
                    <input type="password" name="password" value="">
                    <textarea name="message">Hello</textarea>
                </form>
            </body>
        </html>
        """
        
        # Base URL for action attribute resolution
        base_url = "http://example.com"
        
        # Call the extract_forms function
        forms = extract_forms(html_content, base_url)
        
        # Verify that exactly one form is extracted
        self.assertEqual(len(forms), 1, "The number of forms extracted is incorrect.")
        
        # Verify form action and method
        form = forms[0]
        self.assertEqual(form['action'], "http://example.com/submit", "Form action is incorrect.")
        self.assertEqual(form['method'], "post", "Form method is incorrect.")
        
        # Verify input elements
        inputs = form['inputs']
        self.assertEqual(len(inputs), 3, "The number of input elements is incorrect.")
        
        # Verify each input's name and value
        self.assertEqual(inputs[0]['name'], "username", "First input name is incorrect.")
        self.assertEqual(inputs[0]['value'], "testuser", "First input value is incorrect.")
        
        self.assertEqual(inputs[1]['name'], "password", "Second input name is incorrect.")
        self.assertEqual(inputs[1]['value'], "", "Second input value is incorrect.")
        
        self.assertEqual(inputs[2]['name'], "message", "Textarea name is incorrect.")
        self.assertEqual(inputs[2]['value'], "Hello", "Textarea value is incorrect.")
    
if __name__ == '__main__':
    unittest.main()
