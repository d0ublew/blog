# PHP Code Review 2

<div class="hidden">
    <details>
        <summary>Keywords</summary>
            PwC CTF: Hack A Day 2023 - Securing AI, web, php
    </details>
</div>

## TL;DR

Triggering error to reach `catch` block

## Source Code

> [!INFO]
> This is only a part of the source code

```php
<?php

// php 8.2.12
//
// if ?debug, highlight __FILE__ to view source code

$username = $_GET['username'];
$passwd = $_GET['password'];
$alg = $_GET['alg'];

$pwlist = array('admin' => "REMOVED", "editor" => "REMOVED" );

function hashing($passwd, $alg) {
    try {
        if (!isset($alg)) {
            $alg = "md5";
        }
        $alg = strval(trim($alg));
        $passwd = strval($passwd);
        if ($alg != "md5" && $alg != "sha256") {
            die("invalid algorithm");
        }
        return hash($alg, $passwd);
    } catch (Throwable) {
        return;
    }
}

if (isempty($username) || isempty($passwd)) {
    die("empty username or password");
}

if (!strcmp(hashing($passwd, $alg), $pwlist[$username])) {
    // set cookie with value of xor($username, $flag)
}

?>
```

## Initial Analysis

From the source code above, it is apparent that we need to pass the `strcmp`
checks, such that we could retrieve the flag from the cookie. The first argument
is the hash digest of our provided password (MD5 or SHA256) and the second
argument comes from the initialized array. Since the value of the array is not
fully known, it is almost impossible for us to guess the username's hashed
password.

However, notice that if we provide a username that does not exist in the array,
`$pwlist[$username]` would just return `NULL`. Looking at the `hashing()` function,
we could see that there are two code paths, one that returns `hash($alg, $passwd)`,
and another path that returns `NULL`. Since we could make the second argument to
be `NULL`, it would be great if we could get the `hashing()` function to return
`NULL` as well.

## Analysis of `hashing()`

The code path which returns `NULL`, require us to trigger an error somewhere
inside the `try` block. There are three function candidates, i.e., `isset`,
`strval`, and `trim`. After trial-and-error, the `trim()` function would raise
an error when an array is passed as the argument.

![output of trim()](./img/b.png)

We could re-confirm this behaviour by passing an array to `hashing()` and observe
that it indeed returns nothing as opposed to normal argument like `md5` and `sha256`.

![output of hashing()](./img/a.png)


## Solution

Here is the summary of our findings:

- Our goal is to pass the `strcmp` checks
- We could make the second argument to return `NULL` using non-existing username
- We could make the first argument to return `NULL` by triggering an error via the `trim()` function by passing it an array such that the `catch` block is reached

To pass an array via HTTP query string, we just need to append the parameter name with `[]`, e.g., `?alg[]=abcd`.
Since the cookie value is our supplied username XOR with the flag and base64 encoded, and we do not know the length of the flag beforehand, we could just supply a really long username

The final payload to get the server to set the cookie is:

```text
http://<url>?username=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&password=deadbeef&alg[]=
```
