---
title: Upload Vulnerabilities
desc: >-
  THM: Tutorial room exploring some basic file-upload vulnerabilities in
  websites.
---
## Introduction

In this room, we will be exploring basic file-upload vulnerabilities in web applications. Before we begin, we need to modify our `/etc/hosts` file to include the following:

```
10.10.68.175    overwrite.uploadvulns.thm shell.uploadvulns.thm java.uploadvulns.thm annex.uploadvulns.thm magic.uploadvulns.thm jewel.uploadvulns.thm demo.uploadvulns.thm
```
Note: Remove these lines when terminating the box.

The server can be accessed with one of the following virtual hosts:

  - overwrite.uploadvulns.thm
  - shell.uploadvulns.thm
  - java.uploadvulns.thm
  - annex.uploadvulns.thm
  - magic.uploadvulns.thm
  - jewel.uploadvulns.thm

## Task 2 - Introduction
The ability to upload files to a server has become an integral part of how users interact with web applications. When handled poorly, file uploads can open up severe vulnerabilities in the server leading to anything from a minor nuisance to full Remote Code Execution (RCE) if an attacker manages to upload and execute a shell.

The purpose of this room is to explore some of the vulnerabilities resulting from improper handling of file uploads. More specifically, the room will look at:

  - Overwriting existing files on a server
  - Uploading and Executing Shells on a server
  - Bypassing Client-Side filtering
  - Bypassing various kinds of Server-Side filtering
  - Fooling content type validation checks

## Task 3 - General Methodology
First step to finding file upload vulnerabilities is to find the point of file upload. Enumeration and Recon are key here.

> With a basic understanding of how the website might be handling our input, we can then try to poke around and see what we can and can't upload. If the website is employing client-side filtering then we can easily look at the code for the filter and look to bypass it (more on this later!). If the website has server-side filtering in place then we may need to take a guess at what the filter is looking for, upload a file, then try something slightly different based on the error message if the upload fails. Uploading files designed to provoke errors can help with this. Tools like Burpsuite or OWASP Zap can be very helpful at this stage.

## Task 4 - Overwriting Existing Files
When a file is uploaded to the server, a range of checks should be carried out to ensure that the file will not overwrite an existing file on the server. A common practice is to assign the uploaded file a new name on the server-side. Alternatively, the server may perform a check to see if the file name already exist and return an error in the event the checks are true. File permissions can also assist in preventing files from being overwritten.

To solve this challenge, navigate to `http://overwrite.uploadvulns.thm` and look at the source page. Our aim find a target image we can overwrite.

![File Overwrite Target](../../assets/images/thm/uploadvulnerabilities/01%20-%20File%20Overwrite%20Target.png)

Let's download an image from the internet and rename it to `mountains.jpg`. Upload the downloaded file to overwrite the existing file.

![File Overwrite Flag](../../assets/images/thm/uploadvulnerabilities/02%20-%20File%20Overwrite%20Flag.png)

Retrieved Flag: `THM{OTBiODQ3YmNjYWZhM2UyMmYzZDNiZjI5}`

## Task 5 - Remote Code Execution
In this challenge, we will looking at uploading a file to enable RCE on the server. RCE allows and attacker to execute arbitrary code on the web server. Generally this RCE happens as a low-privileged user (such as `www-data` on Linux servers) but it is a serious vulnerability none-the-less.

Remote code execution via a file upload vulnerability in a web application tend to be exploited by uploading a program written in the same language as the back-end of the website (or another language which the server understands and will execute).

It is worth nothing that in a *routed* application (an application where the routes are defined programmatically rather than being mapped to the file-system), this method of attack becomes a lot more complicated and a lot less likely to occur. Most modern web frameworks are routed programmatically.

There are two basic ways to achieve RCE on a web server when exploiting a file upload vulnerability: webshells and reverse/bind shells. A full featured reverse/bind shell is the ideal goal for an attacker; however a webshell may be the only option available (for example, if a file length limit has been imposed on uploads or if firewall rules prevent any network-based shells).

As a general methodology, we would be looking to upload a shell, then activate it either by navigating directly to the file if the server allows it (non-routed applications with inadequate permissions) or by otherwise forcing the webapp to run the script for us (necessary in routed applications).

For this challenge, our target will be: `http://shell.uploadvulns.thm`

Before we can proceed, we need to enumerate the host to find our upload point on the web application. We can use several tools but in our case we will be using Feroxbuster.

![RCE Ferox Output](../../assets/images/thm/uploadvulnerabilities/03%20-%20RCE%20Shell%20Ferox.png)

We have two possible directories which could be used for uploads. The directory called `/resources` seems the most promising. Let's upload a dummy file to see if our assumption is correct.

![RCE File Upload Verification](../../assets/images/thm/uploadvulnerabilities/04%20-%20RCE%20File%20Upload%20Verification.png)

Looks like our assumption was correct. Let's go ahead and craft a simple web shell to test with first. A simple web shell in PHP can be coded as follows:

```php
<?php
    echo system($_GET["cmd"]);
?>
```
Upload the PHP web shell to the the web application and activate it from the `/resources` directly.

![RCE Shell Upload](../../assets/images/thm/uploadvulnerabilities/05%20-%20RCE%20Shell%20Upload.png)

Since our PHP shell retrieves a command to execute using a GET request, we can execute our shell by inputting the desired commands in the URL as follows:

```
http://http://shell.uploadvulns.thm/resources/shell.php?cmd=whoami;ls;id
```
![RCE Web Shell Execute](../../assets/images/thm/uploadvulnerabilities/06%20-%20RCE%20Web%20Shell%20Execute.png)

Note that it is sometimes better to view the page source code as the formatting of the returned results may be better.

![RCE Web Shell Execute View Source](../../assets/images/thm/uploadvulnerabilities/07%20-%20RCE%20Web%20Shell%20Execute%20Source.png)

Using this method, we can extract the flag located in `/var/www/` directory by systematically finding the name of the flag file and then using cat to output the flag.

```
http://shell.uploadvulns.thm/resources/shell.php?cmd=ls%20/var/www/
http://shell.uploadvulns.thm/resources/shell.php?cmd=cat%20/var/www/flag.txt
```

![RCE Web Shell Flag](../../assets/images/thm/uploadvulnerabilities/08%20-%20RCE%20Web%20Shell%20Flag.png)

Let's try to retrieve this flag using a reverse shell. We can use the PHP reverse shell from: `https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php`

Configure the reverse shell with our `tun 0` IP address, save and upload this to the web application.

![RCE Rev Shell Config](../../assets/images/thm/uploadvulnerabilities/09%20-%20RCE%20Rev%20Shell%20Config.png)

Start a Netcat listner on port `1234` and execute the shell by navigating to the file and clicking on it:

```console
$ nc -lvnp 1234
```
We have a reverse shell!

![RCE Rev Shell](../../assets/images/thm/uploadvulnerabilities/10%20-%20RCE%20Rev%20Shell.png)

Let's retrieve the flag.

![RCE Rev Shell Flag](../../assets/images/thm/uploadvulnerabilities/11%20-%20RCE%20Rev%20Shell%20Flag.png)

Retrieved Flag: `THM{YWFhY2U3ZGI4N2QxNmQzZjk0YjgzZDZk}`

## Task 6 - Filtering
Input filtering is a common defence technique employed by web developers against file upload vulnerabilities. See [[platform.thm.adventofcyber2022.day15]] for more information regarding unrestricted file uploads and strategies to defend against file upload vulnerabilities.

I this challenge, we will be looking at some of the defence mechanisms used by web developers to prevent malicious file uploads and how to circumvent them.

Before we begin, let's discuss the difference between client-side and server-side filtering.
  - **Client-Side**: Client-side in context of web applications means that it is running in the user's browser as opposed to on the web server itself. JavaScript is very common as the client-side language. A client-side script will run in a user's we browser. Client-side filtering is trivial to bypass and as such client-side filtering by itself is a highly insecure method of verifying that na uploaded file is not malicious.
  - **Server-Side**: Server-side scripts run on the server. PHP is predominantly used as a server-side language (with Microsoft's ASP for IIS coming in a close second). Server-side filtering tends to be more difficult to bypass. As the code is executed on the server, it would be impossible to bypass the filter completely; instead the attacker would need to form a payload which conforms to the filters in place while still allowing the attacker to execute the payload.

 With the above in mind, let's look at different kind of filtering.

#### Extension Validation
File extensions can be used to identify the contents of a file. In practice they are very easy to change. Note that Microsoft Windows still uses file extensions to identify file types while UNIX based systems tend to rely on other methods (discussed further below).

Filters that check for file extensions work in one of two ways:
 - Blacklist extensions - have a list of extensions which are not allowed.
 - Whitelist extensions - have a list of extensions which are allowed while rejecting everything else.

#### File Type Filtering
File type filtering is similar to file extension validation but instead looks at HTTP request headers to verify that the contents of a file are acceptable to upload.
  - **MIME Validation**: MIME (or Multipurpose Internet Mail Extension) types are used as an identifier for files. The MIME type for a file upload is attached in the HTTP request header.

  ![MIME Validation](../../assets/images/thm/uploadvulnerabilities/12%20-%20MIME.png)
  <br>
  MIME types (Content-Type) follow the format `/`. I the HTTP request above, an image `spaniel.jpg` with a MIME type (or Content-Type) of `image/jpeg` was uploaded.
  
  The MIME type for a file can be checked client-side and/or server-side. Since MIME type is based on the extension of the file, it is extremely easy to bypass.
  - **Magic Number Validation**: Magic numbers are the more accurate way of determining the content of a file. The *magic number* of a file is a string of bytes at the very beginning of a the file content which identify the content ([List of file signatures - Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)). Unlike Windows, Unix systems use magic numbers for identifying files. This is not a guaranteed solution but it is more effective than checking the extension of the file alone.

#### File Length Filtering
File length filters are used to prevent huge files from being uploaded to the server via an upload form. This technique is most often used to prevent attacks which can potentially starve the server of resources thus preventing (or denying) other users the ability to upload files. These types of attacks are commonly referred to as *denial of service* attacks.

#### File Name Filtering
Typically, files uploaded to a server should be unique. Usually this means adding a random aspect to the file name. Alternatively, developers can check if a file with the same name already exists on the server and provide an error to the user if such is the case. Additionally, file names should be sanitized on upload to ensure that they don't contain any *bad characters* which could potentially cause problems on the file system when uploaded (ie. null bytes or forward slashes or control characters such as `;` and potential unicode characters).

This means that on well administered servers, our uploaded files are unlikely to have the same name we ave them before uploading.

#### File Content Filtering
File content filtering is more complicated as it requires a scan of the full contents of an uploaded file to ensure that it's not spoofing its extension, MIME and magic number. This is a significantly more complex process that majority of the basic filtration systems employed.

## Task 7 - Bypassing Client-Side Filtering
In this task we will be looking at bypassing client-side filtering. As mentioned in the previous section, client-side filtering tends to extremely easy to bypass as it occurs entirely on the machine controlled by the attacker.

There are for easy ways to bypass client-side file upload filters:
  - *Turn off Javascript in your browser* - this will work provided the site doesn't require Javascript in order to provide basic functionality.
  - *Intercept and modify the incoming web request* - using tools like Burp Suite, we can intercept the incoming web request and strip out the Javascript filter before it has a chance to run. More on this below.
  - *Intercept and modify the file upload* - where the methods work before the webpage is loaded, this method allows the web page to load as normal but intercepts the file upload after it's already passed (and been accepted by the filter). More on this below.
  - *Send the file directly to the upload point* - Why use the webpage with the filter when the file can be sent directly using a tool like `curl`? Posting the data directly to the page which contains the code for handling the file upload is another effective method for completely bypassing a client side filter. To use this method, you would first need to intercept a successful upload (using Burp Suite) to see the parameters being used in the upload which can then be slotted into the following command: `curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>`

#### Practical Example
Let's look at a practical example below. Before we can begin, we need to to enumerate the website to find possible location for our uploaded files. Let's upload a test file and then run a tool like `feroxbuster` to enumerate the host.

Looking at the source-page, we find that a client-side filter is being employed with a white-list for file extension `png`.

```javascript
window.onload = function(){
	var upload = document.getElementById("fileSelect");
	var responseMsg = document.getElementsByClassName("responseMsg")[0];
	var errorMsg = document.getElementById("errorMsg");
	var uploadMsg = document.getElementById("uploadtext");
	upload.value="";
	upload.addEventListener("change",function(event){
		var file = this.files[0];
		responseMsg.style = "display:none;";
		if (file.type != "image/png"){
			upload.value = "";
			uploadMsg.style = "display:none;";
			error();
		} else{
			uploadMsg.innerHTML = "Chosen File: " + upload.value.split(/(\\|\/)/g).pop();
			responseMsg.style="display:none;";
			errorMsg.style="display:none;";
			success();
		}
	});
};
```
Let's upload a test image and begin our enumeration.

![Client-Side Filter Bypass](../../assets/images/thm/uploadvulnerabilities/13%20-%20Client%20Side%20Bypass.png)

![Client-Side Directory Enumeration](../../assets/images/thm/uploadvulnerabilities/14%20-%20Client%20Side%20Bypass%20Ferox.png)

![Client-Side Uploads Folder](../../assets/images/thm/uploadvulnerabilities/15%20-%20Client%20Side%20Bypass%20Upload%20Folder.png)

Now that we know where our uploaded files are being stored, let's go ahead and upload our reverse shell. Like before, we will use the following [PHP reverse shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) with the IP address set to our current tun0 IP address and port `1234`.

Rename the reverse shell to have a file extension of `png` in order to bypass the client-side filter.

Let's open Burp Suite and configure our browser to use Burp Proxy. One the vulnerable web application, select our malicious file.

![Client-Side Filter Bypass Shell Selected](../../assets/images/thm/uploadvulnerabilities/16%20-%20Client%20Side%20Bypass%20Shell%20Selected.png)

Ensure *Intercept* is *on* and click *Upload* on the web application to capture the request.Notice the file name and Content-Type in the request header.

![Client-Side Filter Bypass Burp Intercept](../../assets/images/thm/uploadvulnerabilities/17%20-%20Client%20Side%20Bypass%20Burp%20Intercept.png)

Let's modify the filename from `shell.png` to `shell.php` and Content-Type from `image/png` to `text/x-php` and forward the request to the server.

![Client-side Filter Bypass Burp Modification](../../assets/images/thm/uploadvulnerabilities/18%20-%20Client%20Side%20Bypass%20Burp%20Modify%20MIME.png)

![Client-side Filter Bypass Malicious Upload Success](../../assets/images/thm/uploadvulnerabilities/19%20-%20Client%20Side%20Bypass%20Malicious%20Upload%20Success.png)

Let's get our our Netcat listener and execute the payload by navigating to the uploaded file located at: `http://java.uploadvulns.thm/images/shell.php`

```console
$ nc -lvnp 1234
```
We have a shell and our flag.

![Client-side Filter Bypass Reverse Shell](../../assets/images/thm/uploadvulnerabilities/20%20-%20Client%20Side%20Bypass%20Reverse%20Shell.png)

![Client-side Filter Bypass Flag](../../assets/images/thm/uploadvulnerabilities/21%20-%20Client%20Side%20Bypass%20Flag.png)

Retrieved Flag: `THM{NDllZDQxNjJjOTE0YWNhZGY3YjljNmE2}`

## Task 8 - Bypassing Server-Side Filtering: File Extensions
Server-side filters are more difficult to bypass by comparison as we do not have access to the backend filter code. Bypassing server-side filters often involve and iterative process to test and build up a payload which conforms to the filter's restrictions.

Let's begin by looking at web applications that use a blacklist for file extensions as a server side filter. There are a variety of ways this could be coded and the bypass technique used is dependant on that. A simple example code for a blacklist file extension filter is presented below:

```php
<?php
    //Get the extension
    $extension = pathinfo($_FILES["fileToUpload"]["name"])["extension"];
    //Check the extension against the blacklist -- .php and .phtml
    switch($extension){
        case "php":
        case "phtml":
        case NULL:
            $uploadFail = True;
            break;
        default:
            $uploadFail = False;
    }
?>
```
In the example above, the code is looking for the last period `.` in the file name and uses that to confirm the extension. Other ways the code could be working include: searching for the first period in the filename or splitting the file name at each period and checking to see if any blacklisted extensions show up.

In the example code above, we can see that the developers are filtering out `.php` and `.phtml` extensions so if an attacker wanted to upload a PHP script, another extension will need to be used. There are a variety of other more rarely used PHP extensions that web servers may recognize: `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.php-s`, `.pht`, and `.phar`. Many of these bypass the filter (which only blocks `.php` and `.phtml`). Note the other PHP extensions will only work if the server is configured to recognize them as PHP files otherwise the server  will simply attempt to display the content of the file without the server actually executing the file.

Now let's consider a black-box system where we don't have prior knowledge of the source code. The first steps are to enumerate what extensions are permitted and what extensions are blacklisted. Depending on how the filter is implemented, an attacker may be able to append a blacklisted extension to an allowed extension. For example, a server permits `.jpg` extension but filters out `.php` and all of its permutations, a simple payload may include modifying the accepted file extension with a blacklisted one (ie. modify `shell.jpg` to `shell.jpg.php`). This is not guaranteed to work as this is highly dependent on filter configuration but is a good start.

#### Practical Example
Let's look at a practical example. Navigate to: `http://annex.uploadvulns.thm/`

In the terminal box on the web application, type help to get the syntax required to select and upload a file.

Let's go ahead and select an image file and upload it. Using `feroxbuster` we can enumerate the host to find out that our uploaded files are being stored in the `/privacy` folder.

![Server-side Filter Bypass Image Upload](../../assets/images/thm/uploadvulnerabilities/22%20-%20Server%20Side%20Bypass%20Image%20Upload.png)

Let's try uploading our PHP reverse shell.

![Server-side Filter Bypass File Invalid](../../assets/images/thm/uploadvulnerabilities/23%20-%20Server%20Side%20Bypass%20File%20Type%20Invalid.png)

Looks like the extension `.php` is being filtered out. Iterating through the different PHP extensions, it seems that `.php5` is not being filtered and as such we are able to upload it to the server.

![Server-side Filter Bypass PHP5 Upload Success](../../assets/images/thm/uploadvulnerabilities/25%20-%20Server%20Side%20Bypass%20PHP5%20Success.png)

Let's setup up our Netcat listener and execute the payload a: `http://annex.uploadvulns.thm/privacy`

![Server-side Filter Bypass Reverse Shell and Flag](../../assets/images/thm/uploadvulnerabilities/26%20-%20Server%20Side%20Bypass%20Reverse%20Shell%20and%20Flag.png)

Retrieved Flag: `THM{MGEyYzJiYmI3ODIyM2FlNTNkNjZjYjFl}`

## Task 9 - Bypassing Server-Side Filtering: Magic Numbers
Magic numbers are used as more accurate identifiers for files. The magic numbers are a string of hexadecimal numbers which are always the very first thing in a file. With this knowledge, it is possible to use magic numbers to validate file uploads by simply reading those first few bytes and comparing them against either a whitelist or a blacklist. This can be very a technique against PHP based web servers however it can sometimes fail against other types of web servers.

Let's drive right into a practical example.

Trying to upload our PHP reverse shell, we get an error message that only GIFs are allowed.

Before doing anything else, let's run the `file` command on our PHP reverse shell.

```console
┌──(siachen㉿kali)-[/dev/shm]
└─$ file shell.php 
shell.php: PHP script, ASCII text
```
Here we notice that Linux identifies the file correctly as PHP file. We want to pass this file off as a JPEG so let's open up the PHP file and add 4 random placeholder characters to the beginning of the file. The reason we are adding 6 characters is because the magic number has the hex signature of `47 49 46 38 39 61`.

![Magic Number Bypass GIF Signature](../../assets/images/thm/uploadvulnerabilities/27%20-%20Magic%20Number%20Bypass%20GIF%20Signature.png)

Now open the file in `hexeditor` and replace the placeholder characters with the hex signature for a GIF.

![Magic Number Bypass GIF Hex Signature](../../assets/images/thm/uploadvulnerabilities/28%20-%20Magic%20Number%20Bypass%20GIF%20Hex%20Sig.png)

Running `File` on `shell.php` we notice that the Linux now recognizes it as a GIF instead of a PHP file.

```console
┌──(siachen㉿kali)-[/dev/shm]
└─$ file shell.php
shell.php: GIF image data, version 89a, 15370 x 28735
```
Let's select and upload our file to the server.

![Magic Number Bypass File Upload Success](../../assets/images/thm/uploadvulnerabilities/29%20-%20Magic%20Number%20Bypass%20Upload%20Success.png)

We now need to figure out where the file was uploaded to. We can again use `feroxbuster` to enumerate the host and find possible locations. Most likely place found by `feroxbuster` appear to be a directory called `/graphics` but it looks like directory indexing is disabled. We will have to execute the shell by navigating directly to the uploaded file at: `http://magic.uploadvulns.thm/graphics/shell.php`

![Magic Number Bypass Reverse Shell and Flag](../../assets/images/thm/uploadvulnerabilities/30%20-%20Magic%20Number%20Bypass%20Success%20and%20Flag.png)

Retrieved Flag: `THM{MWY5ZGU4NzE0ZDlhNjE1NGM4ZThjZDJh}`

## Task 10 - Example Methodology
Following is a basic methodology on how to approach the task of file upload filter bypass.

1. Look at the web application as a whole to determine what languages and frameworks the web application might have been built with. HTTP request headers intercepted by Burp Suite can provide valuable information about the server.
2. Enumerate the host using tools like `feroxbuster` to look for attack vectors such as an uploads page.
3. Analyze source-code for the web application for any client-side scripts implementing client-side filters.
4. Upload an innocent file and figure out how the uploaded file can be be accessed. This serves to create a baseline accepted file which can be used for further testing. An important switch in `feroxbuster` is `-x` which can be used to look for files with specific file extensions like `.php`, `.txt`, and `.html`. This can be quite useful if an attacker has managed to upload a payload and the server is changing the name of uploaded files.
5. Having ascertained how and where uploaded files are being accessed, attempt a malicious file upload. Any error messages encountered during filter bypass attempts can provide valuable information on the kind of filter being employed.

Assuming that our malicious upload was stopped by the server, here are some ways to ascertain what kind of server-side filter may be in place:

1. If you can successfully upload a file with a completely invalid/random file extension (ie. image.invalidfileformat) then the chances are that the server is using an extension ***blacklist*** filter. If this file upload fails then a ***whitelist*** filter is being employed.
2. Try re-uploading an innocent file accepted by the server but change the magic number to be something you would expect to be filtered. If the upload fails then the server is employing ***magic number*** based filter.
3. As with the previous attempt, try uploading and innocent file accepted by the server but intercept the request with Burp Suite and modify the MIME type (Content-Type) to something that you would expect to be filtered. If the upload fails then the server is filtering on ***MIME*** types.
4. Enumerate file length filters by uploading progressively bigger files until you hit the filter limit. Be aware that a small file length limit may prevent you from uploading the reverse shell we've been using throughout this room.

## Task 11 - Challenge
Let's apply everything we've learnt so far to retrieve a flag from `/var/www/`.

Navigate to `http://jewel.uploadvulns.thm` and begin enumerating the host for more information.

Looking at the page source code, we notice a Javascript file named `upload.js`.

```javascript
$(document).ready(function () {
  let errorTimeout;
  const fadeSpeed = 1000;
  function setResponseMsg(responseTxt, colour) {
    $('#responseMsg').text(responseTxt);
    if (!$('#responseMsg').is(':visible')) {
      $('#responseMsg').css({
        'color': colour
      }).fadeIn(fadeSpeed)
    } else {
      $('#responseMsg').animate({
        color: colour
      }, fadeSpeed)
    }
    clearTimeout(errorTimeout);
    errorTimeout = setTimeout(() =>{
      $('#responseMsg').fadeOut(fadeSpeed)
    }, 5000)
  }
  $('#uploadBtn').click(function () {
    $('#fileSelect').click()
  });
  $('#fileSelect').change(function () {
    const fileBox = document.getElementById('fileSelect').files[0];
    const reader = new FileReader();
    reader.readAsDataURL(fileBox);
    reader.onload = function (event) {
      //Check File Size
      if (event.target.result.length > 50 * 8 * 1024) {
        setResponseMsg('File too big', 'red');
        return;
      }      //Check Magic Number

      if (atob(event.target.result.split(',') [1]).slice(0, 3) != 'ÿØÿ') {
        setResponseMsg('Invalid file format', 'red');
        return;
      }      //Check File Extension

      const extension = fileBox.name.split('.') [1].toLowerCase();
      if (extension != 'jpg' && extension != 'jpeg') {
        setResponseMsg('Invalid file format', 'red');
        return;
      }
      const text = {
        success: 'File successfully uploaded',
        failure: 'No file selected',
        invalid: 'Invalid file type'
      };
      $.ajax('/', {
        data: JSON.stringify({
          name: fileBox.name,
          type: fileBox.type,
          file: event.target.result
        }),
        contentType: 'application/json',
        type: 'POST',
        success: function (data) {
          let colour = '';
          switch (data) {
            case 'success':
              colour = 'green';
              break;
            case 'failure':
            case 'invalid':
              colour = 'red';
              break
          }
          setResponseMsg(text[data], colour)
        }
      })
    }
  })
});
```
The Javascript file implements client-side file size, magic number, and file extension filters. Based on the above code, our file needs to be:
  - Greater than 409.6kb
  - Needs magic number: FF D8 FF
  - Needs file extension: jpg or jpeg

With Burp Suite let's capture a request to the home page. Keep forwarding the requests until a request for `/assets/js/upload.js` is made. Right-click and select `Do intercept - Response to this request` as we want to be able to intercept `upload.js` in Burp Suite to remove the client-side filters. Keep forwarding the requests until we intercept the response we are interested in.

![Challenge Client Side](../../assets/images/thm/uploadvulnerabilities/37%20-%20Challenge%207.png)

Delete the `Check File Size`, `Check Magic Number`, and `Check File Extension` client-side filters and forward the request. This should now allow us to bypass the implemented client-side filters. By capturing the request with Burp Suite, we also find that the server is powered by `ExpressJs with NodeJS`.

![Challenge Burp](../../assets/images/thm/uploadvulnerabilities/34%20-%20Challenge%204.png)

Upload a standard JPEG and enumerate the host to see possible locations where our file could be uploaded to.

![Challenge Initial Feroxbuster Scan](../../assets/images/thm/uploadvulnerabilities/31%20-%20Challenge%201.png)

Looks like three possibilities `/admin`, `/modules`, and `/content`. Let's rerun a `feroxbuster` scan on the `/content` folder using the custom wordlist provided by the challenge. The new scan with the custom wordlist shows a list of JPEG images including the one which we uploaded earlier: `http://jewel.uploadvulns.thm/content/TCK.jpg`

![Challenge Second Feroxbuster Scan](../../assets/images/thm/uploadvulnerabilities/32%20-%20Challenge%202.png)

![Challenge Uploaded JPEG](../../assets/images/thm/uploadvulnerabilities/33%20-%20Challenge%203.png)

Since we know that the web server is powered by NodeJS, let's download a reverse shell from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#nodejs).

Save the reverse shell as `shell.jpg` in attempt to bypass any server-side MIME filters (this is purely a guess at this moment as MIME type filters have not appeared in the challenge). Ensure the IP and port numbers are modified before uploading the file. Looks like using the `.jpg` extension we are able to bypass the server-side MIME filter (note that `shell.js` was tried before this and resulted in failure to upload).

![Challenge Shell](../../assets/images/thm/uploadvulnerabilities/35%20-%20Challenge%205.png)

Let's run another `feroxbuster` scan of the `/contents` folder to track down our renamed shell file.

![Challenge Third Feroxbuster Scan](../../assets/images/thm/uploadvulnerabilities/36%20-%20Challenge%206.png)

Of all the listed files, only `/NEF.jpg` was not an image so it must be our uploaded shell.

Setup a Netcat listener to listen on port 1234 and navigate to and `http://jewel.uploadvulns.thm/admin`.

To execute the payload, enter `../content/NEF.jpg` in the command box and execute to gain our shell.

![Challenge Shell and Flag](../../assets/images/thm/uploadvulnerabilities/38%20-%20Challenge%208.png)

Retrieved Flag: `THM{NzRlYTUwNTIzODMwMWZhMzBiY2JlZWU2}`
