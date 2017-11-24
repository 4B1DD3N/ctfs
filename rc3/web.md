# Web (100)

> Proof that you are not the latest intern at Infinion and solve these easy learning challenges.
> Connection:
> http://35.198.105.104:5474/

```python
#!/usr/bin/env python2

import re
import requests
import sys

url = "http://13.59.6.98/"

def get_flag_char_from_html(content):
    return re.search('<p hidden>.*?</p>', content).group(0).split('>')[1].split('<')[0]

def get_next_html_page(content):
    return re.search('<meta http-equiv="refresh" content="0; url=.*?" />', content).group(0).split('url=')[1].split('"')[0]

flag = ""
uri = ""

while True:
    response = requests.get(url + uri)

    content = response.content

    flag = flag + get_flag_char_from_html(content)

    sys.stdout.write("\r" + flag)
    sys.stdout.flush()

    uri = get_next_html_page(content)

```
