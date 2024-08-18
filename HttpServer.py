from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import logging

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse the path and query string
        parsed_path = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_path.query)

        # Log the incoming GET request details
        logging.info(f"GET request,\nPath: {parsed_path.path}\nQuery: {query}\nHeaders:\n{self.headers}")
        
        # Handle the specific /search path
        if (parsed_path.path == '/search'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            # Respond with the query parameter 'q'
            self.wfile.write(bytes(f"Search results for: {query.get('q', [''])[0]}", 'utf-8'))
        else:
            # Respond with 404 error if the path is not /search
            self.send_error(404, "Page not found")
            logging.info(f"404 Error: Path {parsed_path.path} not found.")

    def do_POST(self):
        # Handle the specific /submit path
        if self.path == '/submit':
            content_length = int(self.headers['Content-Length'])
            post_data = urllib.parse.parse_qs(self.rfile.read(content_length).decode('utf-8'))
            
            # Log the incoming POST request details
            logging.info(f"POST request,\nPath: {self.path}\nHeaders:\n{self.headers}\nBody:\n{post_data}")

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            # Respond with a confirmation message
            self.wfile.write(bytes("Form submitted!", 'utf-8'))
        else:
            # Respond with 404 error if the path is not /submit
            self.send_error(404, "Page not found")
            logging.info(f"404 Error: Path {self.path} not found.")

def run(server_class=HTTPServer, handler_class=MyHandler, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info(f'Starting httpd server on port {port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run()
