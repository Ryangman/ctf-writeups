# CTF League - md2pdf

This challenge was built around several methods of anti-reverse engineering or EDR avoidal methods malware authors often use. Some examples could be tracking whether a program is being debugged/stepped through by monitoring the status of `PTRACE_TRACEME` or determining if a program is being run in a virualized environment and either aborting or altering the behavior to inhibit static analyis.

## Challenge
For the challenge, we were provided with a binary `md2pdf` and markdown messages that had been converted into pdfs using the tool, and an `output.pdf` that contained the flag. Looking at the output.pdf file, it contained what appeared to be random junk, and testing out the `md2pdf.x86`tool on some custom markdown files, we can see it appears to actually encrypt the contents.

Opening the bin in Ghidra,  there aren't any debugging details left in, and no useful looking logic, but there also aren't any of the strings we saw the program print out in our earlier testing.`

```bash
$ strings m2dpdf.x86
...
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
...
```

Running strings on this we can see it mentions that it was "packed", which is a common Anti-Rev/EDR method that involves compressing the logic of an executable file into the data segment of a file, and replacing the code segment with code to "unpack" and execute the actual malware at runtime.

Some quick googling we found the UPX Unpacker and unpacked the file with `upx -d md2pdf.x86`. Analyzing the unpacked binary in Ghidra we now have some useful debugging tools and the actual malicious code. We also had the first flag, which was one of the function names that was unpacked `osu{t3ar_o44_the_w2app1ng_pap3r}`.

Inspecting the unpacked binary, we confirmed that the pdf file output is the encrypted contents of the input file, additionally we can see that the encryption key `derive_key_ecb` is just the first 4 characters of a string `binary_name`.  

```c
void derive_key_ecb(char *binary_name,uchar *key){
  for (i = 0; i < 4; i = i + 1) {
    key[i] = binary_name[i];
  }
  return;
}
```
We tried many possible binary names, such as the md2pdf, ecorp, and other thematically likely names but eventually gave up on that approach, and wrote a script to bruteforce the key.

```c
void xor_chain_cipher(uchar *data,int data_len,uchar *key){
  for (i = 0; i < data_len; i = i + 1) {
    iVar1 = i % 4;
    data[i] = key[iVar1] ^ data[i];
    data[i] = data[i] ^ (key[iVar1] >> 7 | key[iVar1] * '\x02');
    data[i] = ~(key[iVar1] ^ data[i]);
  }
  return;
}
```
The encryption logic was contained in the function `xor_chain_cipher` which we replicated in a python script. Looking at the additional example markdown files from the challenge, all of them began with the header "attention ecorp operatives:", which we used to limit the search of ciphertexts, by assuming that the correctly decrypted script must start with that string:

```bash
$ python3 break.py 
key b'luge'
message: attention ecorp operatives:

We believe TimmyCorp is beginning to pull at the threads. It's important to continue the facade. Our plan must succeed. Await instructions for next week's plan. Winter is coming.

osu{1m_starting_w1th_th3_bin_1n_th3_m1rror}
```
### Solution Script
```py
ctxt ="handout/output.pdf"
string="attention ecorp operatives:"

with open(ctxt, 'rb') as f:
    ciphertext = f.read()

import itertools
lowercase = 'abcdefghijklmnopqrstuvwxyz'
uppercase = lowercase.upper()
charset = lowercase + uppercase
for key_combination in itertools.product(charset, repeat=4):
    key = bytes(''.join(key_combination), 'ascii')
    decrypted = xor_chain_cipher(bytearray(ciphertext), key)

    if decrypted.decode().startswith(string):
        print(f"key {key}")
        print(f"message: {decrypted.decode()}")
        break
```
