# CTFS

```
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_+!{}
```

## CTF TOOLS #

### Linux tricks

Redirect stdout to null (also the default, so >/dev/null is also to stdout)
```
1>/dev/null 
```

Redirect stderr to null
```
2>/dev/null 
```

Redirect  stderr and stdout to null
```
&>/dev/null 
```

### File identification ###
```
file <filename>
```

TrID
```
http://mark0.net/soft-trid-e.html
```

### Handy oneliners ###

Find string with regex expression recursively.
```
grep -RoP "SOME_CTF{.*?}" .
```


Search through all files in the filesystem looking for the sequence `fit{`
```
find / -xdev -type f -print0 | xargs -0 grep -iH "fit{"
```

Search the filesystem for files with setuid permissions
```
find / -perm /u+s
```

Base 64 decode
```
echo string | base64 --decode
```

### Steganography ###

Returns each string of printable characters in files.
Careful use **-a argument** (CVE-2014-8485 [more info](http://lcamtuf.blogspot.be/2014/10/psa-dont-run-strings-on-untrusted-files.html)).
```
strings -a <filename>
```

*Check if `strings` is compiled with ASLR:
```
hardening-check `which strings`
```

Alternatives:
```
hexdump -C <filename>
```

```
od -c <filename>
```

Arnold's cat map
```
https://www.jasondavies.com/catmap/
```

### Crypto

#### RSA

##### Manual

Get information from public keys.
```
openssl rsa -in pubkey.pem -pubin -text -modulus
```

Get the decimal value from the hex modulus and factorize p and q via http://factordb.com/.

Create the private key with p and q (using https://github.com/ius/rsatool).

```
python rsatool.py -p p_value -q q_value -f PEM -o privkey.pem
```

Finally, decrypt the cipher with the private key.

```
openssl rsautl -decrypt -inkey privkey.pem -in cipher.txt
```


##### Automated

One liner solution (using https://github.com/Ganapati/RsaCtfTool). 

The tool uses factordb too, but it can't parse scientific notation.

If the tool fails (because the modulus size is large) use the "manual" way described above.
```
python RsaCtfTool.py --publickey PublicKey.pem --private --uncipher ciphertext.txt
```

### MISC
#### JSFuck
[JSFuck](http://www.jsfuck.com/) is an esoteric and educational programming style based on the atomic parts of JavaScript. It uses only six different characters to write and execute code. [Online deobfuscating!](https://enkhee-osiris.github.io/Decoder-JSFuck/)
```
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!! ......
```

### Cracking


#### Zip

Extract password hashes to file.
```
zip2john test.zip > zip.hashes
rar2john test.rar > rar.hashes
```

Crack the password hash.
```
john zip.hashes
```

Crack the password using a dictionairy.
```
fcrackzip -u -D -p passwords.txt test.zip
```


### Reversing

Information about the binary.
```
exiftool binary
```

Decompress binary packed with UPX.
```
upx -d binary
```

Find all the strings in the binary.
```
strings binary
```

Or find all strings in the binary with radate.
```
rabin2 -z binary
```

Find all the system calls (write, strcmp, etc) in the binary.
```
strace binary
```

Find all the library calls (glibc etc) in the binary.

```
ltrace binary
```

Patch binary with radare2 (wa?), open file in write mode.
```
r2 -w binary
```

Analyze the binary (symbols, references, etc)
```
r2 binary
aaaa
```

- List symbols with "afl".
- Seek to address with "s 0x123"
- Print dissasembly with "pdf" of "pd 20" for 20 instructions
- VV (visual graph)
- pdf~sub (search all sub instructions)
- pdf~.. (show pdf with GNU less)
- S (show sections)
- iS
- V (p for more, q for quit)
- V!
- dcu 0x123 (continue until address)
- dcu entry0
- drr (every register and what they are pointing to)
- pxr @ rsp (get info about the stack)
- dmh (heap analyse)
- pdf@main~call (print all the function calls to glibc)
- drt (show registers)
- dr?eax (show eax register)
- dr eax=0x1 (set eax to 1)
- iz (show srings, izz for whole binary)
- dr rip=0x123 (set next executed instruction at 0x123)
- dr (show registers)
- doo AAA (reopen in debug mode with AAA argument)
- drj (show registers in json)
- dso (step over call)
- wz idk @ rdi (write to rdi)

Reopen in debugging mode
```
doo
```

Set breakpoint
```
db 0x123
```

Continue debugging
```
dc
```

Single step, but current seeked address does not change.
```
ds
```

Seek to the RIP
```
sr rip
```

Print current dissasembled instruction (pdj for json format)
```
pd 1
```

Load debugging profile (env, args, etc)
```
e dbg.profile=profile.rr2
```

### Recon
```
1. Check for names (friends, animals, favourite places, etc)
2. Check images for EXIFF => useless on imgur, facebook, twitter & instagram
3. Check for unusual content => other language?
4. Check for unusual behavior
5. (Twitter) Check following & followers
5. (Facebook) Scan target's account with tool : https://stalkscan.com/
6. If appliable, check for close contacts and repeat 1-5.
7. If 6 didn't have much result try to social engineer target's close friends.
```
### Web
```
"; echo $(ls) #
```

#### XXE

```
<!DOCTYPE XXE_TEST [<!ENTITY xxe SYSTEM "file:///home/flag.txt" >]>
<root>
<flagread>&xxe;</flagread>
</root>
```

### Java

Decompile java bytecode (.java).

```
jad -p DecompileMe.class
```

### Python

Decompile python bytecode (.pyc). https://github.com/Mysterie/uncompyle2

```
uncompyle6 crackme3.pyc
```
