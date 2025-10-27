# CTF League - Elevator

## Overview
This challenge involved using various unix command line tools and related knowledge to progress through levels by finding the credentials of the next user.

#### Level 0
The first level had the users credentials file placed within a subdirectory of the users `home`, which could be found using `cat dir/filename.txt`

#### Level 1
The next user had deeply nested directories that could not be searched manually, using the command `find creds .` searched for the term `creds` recursively from the current directory, eventually finding the file that contained the next levels credentials, which could be output with `cat`

#### Level 2
The third user had one file containing the entire Gutenberg Bible. Using `grep "user" file.txt` and `grep "password" file.txt` we could find the next levels credentials without manually searching the whole file.

#### Level 3
The fourth users had a bash script that would print the credentials for the next level, but it wasn't executable. Running `chmod +X filename.sh` made the script executable, allowing us to run the file and gain the next users credentials.

#### Level 4
The fifth users had the next levels credentials contained in a hidden file. Using the command `ls -h` showed hidden files which could then be read for the credentials. 

#### Level 5
The sixth user had the next level credentials contained in a file whose path contained invalid charachters such as " ". These can be accessed with tab autocomplete which autofills the proper escape characters. This uer also had permsissions for the flag1 file, located at the root directory.

#### Level 6
The seventh  users  hint suggested that they were running a web server but had potentially exposed their password while starting it. Running `top -u $(whoami)` gave us a list of processes running started by the current user, which included a `server.sh` process. We could then run `ps -fp <PID>` with the Process Identifier of the process to recieve the following output, which contained the command which initiated the process, including the credentials
```
UID          PID    PPID  C STIME TTY          TIME CMD
level6_+  106713  106710  0 01:39 ?        00:00:00 /bin/bash /home/level6_53160/server.sh --username=level7_53160 --password=3dbd5e
```

#### Level 7
The eighth user was involved simply exiting vim, which was done by entering command mode by pressing `ESC`, and running `:q!` which exits without saving changes.

#### Level 8
The ninth users hint suggested the credentials may be hidden in a git commit message. Inspecting the .git directory, there is a file `COMMIT_EDITMSG` that contains the next users password. This COMMIT_EDITMSG file is a temporary file that git stores the commit message in while editing, if a commit fails, the message persists in this file.

#### Level 9
The tenth users hint suggested their PC had crashed while saving the credentials. This is confirmed by the existence of a `.txt.swp` file which saved the temporary changes. Running `cat` on this file gave slightly corrupted data evidenced by the "???" which vim inserted, but the username and password where still clearly visible.

#### Level 10
The final level contained the flag file in the root directory, which running `cd /` navigated to, and could then be output via cat.
