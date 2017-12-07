```python
#!/usr/bin/env python2

import r2pipe
import string
import sys
import time

print('Starting exploit...')

# r2 = r2pipe.open('unknown')

# r2.cmd('doo ' + ('a' * 56))

# r2.cmd('db 0x401c84')

# flag = "TUCTF{w3lc0m3"

flag = ""

for i in xrange(56):
    for character in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_+!{}':
        # character = chr(character)
        # print character
        # if character == '"' or character == "'" or character == ':':
        #     continue
        possible_flag = flag + character + ((56 - len(flag) - 1) * 'a')
        # print "Possible flag: ", possible_flag, "Length: ", len(possible_flag)
        # print "Reopening with flag: ", possible_flag
        
        r2 = r2pipe.open('unknown')
        r2.cmd('doo ' + str(possible_flag))
        
        # set length flag in edx
        r2.cmd('db 0x401c74')
        r2.cmd('dc')
        r2.cmd('dr edx=' + str(len(flag)))
        r2.cmd('db 0x401c84')
        r2.cmd('dc')
        
        registers = r2.cmdj('drj rax')
        
        r2.cmd('quit')

        # print "Flag: " + flad
        # print registers

        rax = registers['rax']
        # print "Registers: ", registers
        # print "Rax: ", rax

        # time.sleep(0.05)        
        
        # close r2?
        # print "Rax: ", rax
        if rax == 0:
            # r2.cmd('')
            flag += character
            sys.stdout.write("\r" + flag)
            sys.stdout.flush()
            # print(flag)
            break

```
