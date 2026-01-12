# CTF League - cowsay

## SQL Injection

SQL injection is one of the most common vulnerabilities (#5 in OWASP top 10), that is introduced by the mishandling of user input. If user input is passed to a SQL query by simple string replacement, manipulating that user input can allow executing arbitrary statements against a database. This can be solved using prepared statements, which prevent user input from being interpreted as executable code. 

## Flag 1
The first challenge provided an simple form with a username and password inputs which directly executed the query `SELECT id, username, password FROM user WHERE username ='<input>' AND password ='<input>';`, where the form fields were substituted into. using either input field, we can escape the username and password strings and add SQL such as `OR 1=1`, the make the `WHERE` clause always evaluate to true, regardless of the correctness of the username/password combination. 

We used the password input of `asdf' OR 1=1;-- `. The `asdf'` closes the AND password = 'asdf' query, then the `OR 1=1;` adds the always truthy condition to the `WHERE` clause and ends the query. The final `-- ` comments out the built-in `';` which allows our malicious statement to compile.

Submitting this creates a logged on session, which provides access to another page containing a prompt that is passed to the linux program `cowsay`. The first step here is to try to escape the quotes that are directly passed to `cowsay`. Our first attempt was to simply send a closing quote, we found that sending the input `''` would correctly execute `$ cowsay ''''`, which resulted in cowsay printing the first empty string, and the second pair of quotes being interpreted as a nop. Using bash syntax of `&&` we could add additional commands that would be run by the server, such as `' && ls &&'`. Note the second `&&` is necessary to ensure the final '' is properly treated as a nop. After some digging we found a file on the server called  `flag.txt` which contained the flag, accessible by providing `' && cat /flag.txt && ` to the `cowsay` prompt.

## Flag 2
The second flag was contained in a similar admin portal which contained a username and password form. For this page, we were also provided with the source code for the login route.

```php
// build query
$query_str = "SELECT id, username, password FROM users WHERE username='$username';";
echo '* <b>Query:</b> ' . htmlentities($query_str) . '<br>';

$conn = get_connection();
$result = $conn->query($query_str);
$login_success = false;

// check if any rows were returned?
if ($result->num_rows > 0) {
    // iterate over each row
    while ($row = $result->fetch_assoc()) {
        // compare the password hash stored in the database with the submitted password
        // if (password_verify($_POST['password'], $row['password'])) {
        if ($password === $row['password']) { // XXX: TODO implement password hashing
            $login_success = true;
            $username = $row['username'];
            $_SESSION['username'] = $row['username'];
            $_SESSION['userid'] = $row['id'];
            echo '<b>Welcome! <a href="index.php">Click here</a> to continue.</b><script>window.location = "index.php";</script>';
        }
    }
```

Investigating the authentication logic here, apart form unhashed passwords, the biggest thing that sticks out is that if it finds multiple users of the same username, it checks both of them. While we don't have a form to create a new user, using SQL injection we can do this on our own. The way i chose to do this was using the SQL feature `UNION SELECT` Which allows me to combine the results of 2 selections into one table, and because SQL allows you to "SELECT" a hardcoded value (that doesn't actually need to be in the table), we can introduce any arbitrary userid, username and password combination to the auth system. This is achieved by sumbitting a username such as the following:

```sql
admin' UNION SELECT 1, 'admin', 'test' FROM users; -- -
```
The first select (built into the php code above) queries for the username admin, and the UNION SELECT, "queries" a hardcoded row with our custom parameters. Which produces a result similar to the table below:
```
+--------+----------+----------------+
| userid | username | password       |
+--------+----------+----------------+
|      1 | admin    | actualpassword |
|      1 | admin    | test           |
+--------+----------+----------------+
```
Because of the lack of handling for duplicate accounts in the authentication logic, the query sees the above two rows returned, and checks both of them, including the false entry I made via the union select. By submitting the form with the above username and password of 'test' (or whatever you set in the UNION SELECT), we can make the password check succeed, and create a new session for the username we set in the union select. In a sense, we are ephemerally changing the password of the admin account to whatever we want, and using that new password to log in.

After this succesfully logged us in, we are dropped into a simple notetaking application, within the headers it says 
> "The flag is stored in one of the first notes created (but by a different user)"

```php
if (is_admin()) {
    if (isset($_GET['id'])) {
        $id = intval($_GET['id']);
        
        $conn = get_connection();
        $stmt = $conn->prepare('SELECT id, title, body FROM notes WHERE id=?');
        $stmt->bind_param('i', $id);
        $stmt->execute();
        $stmt->bind_result($noteid, $title, $body);
        if ($stmt->fetch()) {
```

From the url params, our users first note is `id=4`, and a quick look at the source code reveals that the only guardrails when requesting a note by id is that you are an admin, not specifically the author of the note. Modifying the url, we found the flag in note `id=2.`