---
title: Day 16 - Secure Coding (SQLi)
desc: >-
  Day 16 covers topics related to Structured Query Language (SQL) and SQL
  injections. The topics guide the user through techniques to mitigate SQL
  injections and strategies to write secure PHP code when accessing databases.
---
## Introduction

SQL is the traditional languages used to query databases for information. Any application that relies on a databases needs to be able to create SQL syntax on the fly and send them to the database engine to retrieve the required information.

The application used in today's challenge uses `MySQL` as a backend database. `MySQL` stores information in structures called `tables`. Each `table` consists of `columns` (field of data) and `rows`.

To query information from a database, the `SELECT` statement can be used in conjunction with the `columns` and `rows` we want to retrieve from a specific table. For example:

```sql
SELECT * FROM toys;
```

Here we are selecting all columns (indicated by *) from the table named toys. To retrieve specific columns, we can use a comma-separated list of columns.

```sql
SELECT name, quantity FROM toys;
```

To retrieve a specific row, we can append the query with a `WHERE` statement followed by our condition.

```sql
SELECT id FROM users WHERE id = 1;
```

## SLQ Injection (SQLi)

Vulnerabilities SQLi can arise when a web-application takes untrusted input from a user and concatenates it to an SQL question without sanitizing the input. Using SQLi, threat actors can attempt to get a server to run complex SQL queries and potentially dump any data on any table they want.

## Fixing SQLi by Data Type Validation

One of the easiest and most effective ways to prevent SQL injections is to ensure that any data that the user can manipulate that you are concatenating as part of an SQL statement is actually from the type you expect.

Let's look at an example of sending SQL queries from PHP.

```php
$query="select * from users where id=".$_GET['id'];
$elves_rs=mysqli_query($db,$query);
```

The above code takes the `id` parameter from the URL and concatenates it to an SQL query. For example, if the expected data type for `id` is an integer then any user input in the `id` parameter should be converted to an integer. In PHP, `intval()` function can be used to return the integer value of a string.

```php
$query="select * from users where id=".intval($_GET['id']);
$elves_rs=mysqli_query($db,$query);
```

With the above code modification, if an attacker sends an SQLi payload via the `id` parameter, the code will convert the input to an integer before concatenating it as part of the SQL statement. Any malformed input would simply return a zero.

## Fixing SQLi Using Prepared Statements

Prepared statements need to be used if the web-application needs to allow a user to pass arbitrary strings through a parameter (ie. search field).

An example of a vulnerable SQL search query in PHP is presented below:

```php
$query="select * from toys where name like '%".$_GET['q']."%' or description like '%".$_GET['q']."%'";
$toys_rs=mysqli_query($db,$query);
```

Here the `q` parameter gets concatenated twice into the same SQL sequence. The problem with building SQL queries in PHP is that database has no other option but to trust what is being given. If an attacker somehow injects SQL, PHP will blindly concatenate the injected payload into the query string and the database will execute it. The safest way to remedy this problem is to use prepared statements.

Prepared statements allow separation of the syntax of the SQL query from the actual parameters used on the `WHERE` clause. Instead of building a single string by concatenation, you will first describe the structure of the SQL query and use placeholders to indicate the position of the query's parameters. You will then bind the parameters to the prepared statement in a separate function call. Essentially, instead of providing a single SQL query string, we will send dynamic parameters separately from the query itself, allowing the database to piece together securely without depending on PHP.

This can be done by first modifying the initial query by replacing any parameter with a place holder indicated by `?`. This tells the database we want to run a query that takes two parameters as inputs. The query will then be passed to the `mysqli_prepare()` function instead of the usual `mysqli_query()`. `mysqli_prepare()` will not run the query but will indicate to the database to prepare the query with the given syntax. This function returns a prepared statement.

```php
$query="select * from toys where name like ? or description like ?";
$stmt = mysqli_prepare($db, $query);
```

To execute the query, MySQL needs to know the value to put on each placeholder we defined before. `mysqli_stmt_bind_param()` function can be used to attach variables to each place holder. The function requires you to send the following function parameters:

- The first parameter should be a reference to the prepared statement to which to bind the variables.
- The second parameter is a string composed of one letter per place holder to be bound; where letters indicate each variable's data type. In our example, since we are passing two strings, we use `"ss"` in the second parameter. You can use `"i"` for integers or `"d"` for floats.
- Lastly, you need to pass the variables themselves. You must pass as many variables as placeholders defined by `?` in the query.

```php
$q = "%".$_GET['q']."%";
mysqli_stmt_bind_param($stmt, 'ss', $q, $q);
```
Once the statement is created and parameters bound, the prepared statement can be executed using `mysqli_stmt_execute()` which receives the statement `$stmt` as its only parameter.

```php
mysqli_stmt_execute($stmt);
```
When the statement has been executed, we can retrieve the corresponding result set using the `mysqli_stmt_get_result()`. We can assign the result set to the `$toys_rs` variable as in the original code.

```php
$toys_rs=mysqli_stmt_get_result($stmt);
```
Putting the above together results in the following code:

```php
$q = "%".$_GET['q']."%";
$query="select * from toys where name like ? or description like ?";
$stmt = mysqli_prepare($db, $query);
mysqli_stmt_bind_param($stmt, 'ss', $q, $q);
mysqli_stmt_execute($stmt);
$toys_rs=mysqli_stmt_get_result($stmt);
```

## CTF Questions

Ask the elves to run the check on the webapp. Elf Exploit indicates that by injecting `http://Machine_IP/webapp/elf.php?id=1 or 1=1 limit 4,1` He was able to was able to manipulate the DB into returning a specific elf record. Open `elf.php` and modify at the PHP code as follows to fix the vulnerability.

```php
<?php
    include "connection.php";

    #$query="select * from users where id=".$_GET['id'];
  $query="select * from users where id=".intval($_GET['id']); // Fixed vulnerability
    $elves_rs=mysqli_query($db,$query);

    if(!$elves_rs)
    {
        echo "<font color=red size=10>Error: Invalid SQL Query</font>";
        die($query);
    }

    // Get the first result. There should be a single elf here.
    $elf=mysqli_fetch_assoc($elves_rs);

    //Now get the toys associated to this elf
    $query="select * from toys where creator_id=".intval($_GET['id']); //Fixed vulnerability
    $toys_rs=mysqli_query($db,$query);

    if(!$toys_rs)
    {
        echo "<font color=red size=10>Error: Invalid SQL Query</font>";
        die($query);
    }

?>
```
Asking the Elves to run the check again shows no more vulnerabilities in `elf.php` and reveals the first flag `THM{McCode, Elf McCode}`.

Elf Exploit however reveals that the file `search-toys.php` is exploitable using `http://Machine_IP/webapp/search-toys.php?q=99999' union all select null,2,username,password,null,null,null from users -- x`. Open the file and modify the PHP code as follows to fix the vulnerability to get the second flag `THM{KodeNRoll}`.

```php
<?php
include "connection.php";

//The following lines of code fix the vulnerability
#$query="select * from toys where name like '%".$_GET['q']."%' or description like '%".$_GET['q']."%'";
$q="%".$_GET['q']."%";
$query="select * from toys where name like ? or description like ?";
$stmt=mysqli_prepare($db,$query);
mysqli_stmt_bind_param($stmt,'ss',$q,$q);
mysqli_stmt_execute($stmt);
$toys_rs=mysqli_stmt_get_result($stmt);
#$toys_rs=mysqli_query($db,$query);

if(!$toys_rs)
{
    echo "<font color=red size=10>Error: Invalid SQL Query</font>";
    die($query);
}

?>
```
Elf Exploit states that he  can inject SQL to force the DB into returning Evan Nowell as one of the receivers of an Animal Farm, even if Evan didn't get enough Goodboy Score to get that present. You can access here to see what I mean: `http://Machine_IP/webapp/toy.php?id=1 or 1=1 limit 4,1`. If you access the regular link for the Animal Farm, you'll see that Evan isn't one of the receivers.

This vulnerability can be fixed by modifying the PHP code in `toy.php` as follows to get the third flag `THM{Are we secure yet?}`.

```php
<?php
    include "connection.php";

    #$query="select * from toys where id=".$_GET['id'];
    $query="select * from toys where id=".intval($_GET['id']); //Fixed vulnerability
    $toys_rs=mysqli_query($db,$query);

    if(!$toys_rs)
    {
        echo "<font color=red size=10>Error: Invalid SQL Query</font>";
        die($query);
    }

    // Get the first result. There should be a single elf here.
    $toy=mysqli_fetch_assoc($toys_rs);

    //query info on the creator elf
    $query="select * from users where id=".$toy['creator_id'];
    $elves_rs=mysqli_query($db,$query);

    if(!$elves_rs)
    {
        echo "<font color=red size=10>Error: Invalid SQL Query</font>";
        die($query);
    }

    // Get the first result. There should be a single elf here.
    $elf=mysqli_fetch_assoc($elves_rs);

    //query info on planned deliveries
    #$query="select * from kids where assigned_toy_id=".$_GET['id'];
    $query="select * from kids where assigned_toy_id=".intval($_GET['id']); //Fixed vulnerability
    $kids_rs=mysqli_query($db,$query);

    if(!$kids_rs)
    {
        echo "<font color=red size=10>Error: Invalid SQL Query</font>";
        die($query);
    }
?>
```
Elf Exploit reports that he can bypass the login screen at: `http://Machine_IP/webapp/login.php` with SQL injection in the username. If you want to try it, just use any password with this as your username: `' OR 1=1-- x`. Let's modify the `$_POST` parameters to fix the vulnerability and get the fourth flag `THM{SQLi_who???}`. The vulnerability exists in both the `username` and `password` field so we need to account for both in the fix.

```php
<?php
require_once("connection.php");
session_start();

if(isset($_POST['username']) && isset($_POST['password'])){
    $username=$_POST['username'];
    $password=$_POST['password'];

  //The following lines of code fix the vulnerability
  #$query="select * from users where username='".$username."' and password='".$password."'";
    $query="select * from users where username=? and password=?";
    $stmt=mysqli_prepare($db,$query);
    mysqli_stmt_bind_param($stmt,'ss', $username, $password);
    mysqli_stmt_execute($stmt);
    $users_rs=mysqli_stmt_get_result($stmt);
    #$users_rs=mysqli_query($db, $query);

  if(mysqli_num_rows($users_rs)>0)
    {
        $_SESSION['username']=$username;
        echo "<script>window.location='admin.php';</script>";
    }
    else
    {
        $message="Incorrect username/password found!";
        echo "<script type='text/javascript'>alert('$message');</script>";
    }
}
?>
```