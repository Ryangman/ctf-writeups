# CTF League - Decryption As A Service

## Background
In this challenge, we are provided with the scenario that our company had been hit with by a ransoware actor that encrypted our `flag.txt` file. On their website, they are serving a `.git` directory, and we needed to recover some secret from that to decrypt our files. 

## Solve
Given that we already had the encrypted `flag.txt` file, we decided to look at the `decrypt.py` script that was linked from the ransomware site. Examining the cryptographic methods used here, we would need to find the RSA private key used by the ransomware company, and we would be able to decrypt the flag.

```py
prv_key_raw = os.environ.get('PRIVATE_KEY', None)
    if prv_key_raw is None:
        print('Please set the PRIVATE_KEY environment variable first.')
        print('(This mode is for EvilCorp employees only. EvilCorp customers (victims) should')
        print('request their decryption key from EvilCorp and use the "data file" mode instead.)')
    else:
        prv_key = rsa.PrivateKey.load_pkcs1(prv_key_raw.encode('ascii'))
        file = input('Key file: ')
        with open(file, 'rb') as f:
            sym_key = rsa.decrypt(f.read(), prv_key)
        print('Here\'s your symmetric key: ', sym_key.decode('ascii'))
        print('Please provide this key to the customer and tell them to use this script\'s "data')
        print('file" mode to decrypt their file(s).')
```

The ransomware site was functioning as a simple file server and would serve any file from the .git directory if requested, but it was not possible to simply clone the repo to our local machine and investigate it naturally, so we needed to methodically inspect specific files. The standard `.git` file structure is as follows:

```bash
$ tree -L 1 .git/
.git/
├── COMMIT_EDITMSG
├── HEAD
├── ORIG_HEAD
├── branches/
├── config
├── description
├── hooks/
├── index
├── info/
├── logs/
├── objects/
├── packed-refs
└── refs/
```

One region of particular interest is the `logs/HEAD` route, which stores the data used by the `git reflog` command. Requesting that file with https://decryption-as-a-service.ctf-league.osusec.org/.git/logs/HEAD returned us history of the git repo:

```
0000000000000000000000000000000000000000 5b59524be5198f539d44bfc524da9738014673d5 John Wilson <jwilson@e-corp.net> 1769616190 -0800	commit (initial): Add README.md file
5b59524be5198f539d44bfc524da9738014673d5 223e07365ade525603ee94d24196ca62283b50b5 John Wilson <jwilson@e-corp.net> 1769620321 -0800	commit: Add v1 of malware.py
223e07365ade525603ee94d24196ca62283b50b5 af1ebe5e3da4dd395ed098b69c78097bdb76f0f8 John Wilson <jwilson@e-corp.net> 1769620673 -0800	commit: Add decryption script
af1ebe5e3da4dd395ed098b69c78097bdb76f0f8 00ee5738e88aa197cc081b46e35e1ef0465bf99d John Wilson <jwilson@e-corp.net> 1769622099 -0800	commit: Create DaaS web site
00ee5738e88aa197cc081b46e35e1ef0465bf99d c26581c478ce1fc221396bc78bef0dc6d5a2def8 John Wilson <jwilson@e-corp.net> 1769622681 -0800	commit: Woops! Didn't mean to commit my own .env file
c26581c478ce1fc221396bc78bef0dc6d5a2def8 af1ebe5e3da4dd395ed098b69c78097bdb76f0f8 John Wilson <jwilson@e-corp.net> 1769624057 -0800	rebase (start): checkout HEAD~3
af1ebe5e3da4dd395ed098b69c78097bdb76f0f8 3feb75709036c51cdc592af549ee74619611b482 John Wilson <jwilson@e-corp.net> 1769624057 -0800	rebase (fixup): Add decryption script
3feb75709036c51cdc592af549ee74619611b482 14b5ee8077df3439ce5ef0a1d820335548028c56 John Wilson <jwilson@e-corp.net> 1769624057 -0800	rebase (pick): Create DaaS web site
14b5ee8077df3439ce5ef0a1d820335548028c56 14b5ee8077df3439ce5ef0a1d820335548028c56 John Wilson <jwilson@e-corp.net> 1769624057 -0800	rebase (finish): returning to refs/heads/master
14b5ee8077df3439ce5ef0a1d820335548028c56 c577acec01ae797eb6d217cfaed747261abec655 John Wilson <jwilson@e-corp.net> 1769630038 -0800	commit: Add warnings to README

```
The first thing that jumps out here is commit `c26581c4` where they commited their `.env` file to version control. The commit message indicates that they removed the file from the repo, which requesting https://decryption-as-a-service.ctf-league.osusec.org/.env confirms. However, git maintains extensive history in the `.git/objects` directory. 

Whenever a file is commited, it is compressed and stored in this directory based on its sha1 hash, where the first 2 characters of a hash are the directory, and the remaining are the file name. Git creates objects for commits, tags, trees, and files which are stored in a nested structure that allows it to receate the repo at any point in time.

We then could request and download the object of that commit with https://decryption-as-a-service.ctf-league.osusec.org/c2/6581c478ce1fc221396bc78bef0dc6d5a2def8. With the object download we inflated it using the zlib-compression algorithm that git uses internally with 

```bash
$ zlib-flate -uncompress < 6581c478ce1fc221396bc78bef0dc6d5a2def8 | cat
commit 258tree d42282caf7c76740d61836aec147b87526a461c3
parent 00ee5738e88aa197cc081b46e35e1ef0465bf99d
author John Wilson <jwilson@e-corp.net> 1769622681 -0800
committer John Wilson <jwilson@e-corp.net> 1769622681 -0800
```

Next we can get the tree structure from the server, and inflate it as well, which failed due to incorrect header check. Inspecting the magic bytes of the file, it doesn't match any valid the bytes of any method of zlib compression according to [wikipedias list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
```bash
$ xxd xxd d42282caf7c76740d61836aec147b87526a461c3 | less
00000000: 55dc 7762 1105 ....
```

This confused us for a while, but we eventually realized we had overlooked a line at the bottom of the `README.md` file. This tree object had been encrypted by the same malware our `flag.txt` had been, and was useless unless we could decrypt it.

> "**ALSO DON'T RUN THE MALWARE ON YOUR COMPUTER OR IT MIGHT DELETE SOME OF YOUR IMPORTANT GIT FILES!!!**"

However, because git doesn't store diffs, but rather snapshots, every commit object contains every file at that point in history, so we just had to try a different commit that the `.env` might've been present in. We choose the previous commit `00ee5738e88` following the same route. Following the hashes from commit -> tree -> blob we eventually get to the `.env` file. We can then move the compressed object into a mock git repos `.git/objects` directory with using the same hash addressable object structure as we request them, and use the `git cat-file` command to pretty print the file and get the Private Key:
```bash
$ git cat-file -p e7c5357139cf4fdc7b4af389e5493bf053742dec
PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIBPAIBAAJBALh52gPnTQt6LtV3zZD5z+zEfhhCLNZjZAQcLLGBCmJS0O1BW6O0\ntK3uDZLIYd4TInyIp8tw8yDsV+V78BPFcwECAwEAAQJAPHfkmKb2wC5ar6pHfaAF\nIcz+sCDw5Y1KuXYqyDxNw704vZnL4b7de1wH1N/1zGDI1EXWjGPeit6OT7l8agO1\nqQIjAPgbnG6LDVezr4afwtpS7C0yWOkV9f+ZPCAfJOhMlobQdO8CHwC+WBMCGhO4\nXMaeX+D95ebh8QBFsn1eSTLotFcE9w8CIm5miuM9iMBfulkjOedAQsuRvbJqDT6h\nBvocIaYkfk6a740CHwCBlmDKi4pld/RZGpmJAh5gML2otc4YhOk9+JlN7g0CIgog\nX5NfWtQ5U5GCYiEowDK7cGMy0WM5msZvWW0/3ehJyUc=\n-----END RSA PRIVATE KEY-----\n"
```

We can then use this private key with the `decrypt.py`, the encrypted `flag.txt`, and the provided key file to decrypt the flag.