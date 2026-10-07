import email, email.policy, sys
from html.parser import HTMLParser

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.href = None
        self.text = ''
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.href = dict(attrs).get('href')
            self.text = ''
    def handle_data(self, data):
        if self.href is not None:
            self.text += data
    def handle_endtag(self, tag):
        if tag == 'a' and self.href is not None:
            print(repr(' '.join(self.text.split())), '->', self.href)
            self.href = None

m = email.message_from_binary_file(open(sys.argv[1], 'rb'), policy=email.policy.default)
for part in m.walk():
    if part.get_content_type() == 'text/html':
        parser = Links()
        parser.feed(part.get_content())
        parser.close()