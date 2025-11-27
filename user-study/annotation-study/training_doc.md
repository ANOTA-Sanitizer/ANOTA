# User Study Documetnation
## Introduction
Welcome to the ANOTA user study. ANOTA is a framework designed to detect business logic vulnerabilities by allowing users to define the application's intended behavior through annotations.
Your goal is not to fix the bugs in the code. Your goal is to define the security policy of the application using annotations.
## Guiding Principles for Annotation
To use ANOTA effectively, you do not need to annotate every line of code. Follow these core principles to determine where and how to write annotations.

A. Identify Security-Critical Boundaries
Annotations are typically applied at security-critical boundaries where data crosses trust domains. Focus your efforts on:
* Input Handling: Where external data enters the application (e.g., HTTP requests, file uploads).
* System Interactions: Where the application talks to the operating system (e.g., file system access, network requests).
* Privileged Logic: Code sections that should only be accessible to authenticated or administrative users.

B. Derive Policy from Documentation
Do not guess the code's intent based solely on variable names, as the code itself might be buggy. Effective annotations are often derived from:
* Documentation: Read the function docstrings or project README. If a document states "This function only serves images from the /static folder," you should annotate that strict restriction.
* API Specifications: Check if endpoints are intended for admins only or public users.
* Constants: Look for constant variables (e.g., ROOT_DIR) that define intended limits.

## Annotation Syntax Reference
The annotation syntax mimics standard function calls. While the implementation is evolving, use the following "function-like" syntax for this study.

### System Call Control `anota_SYSCALL`
Use this to control how the application interacts with the OS. You can use a blocklist (forbid specific bad actions) or an allowlist (permit only specific actions). Participants often find blocklists easier to construct.

#### General Wrapper Syntax:

```Python
anota_SYSCALL_BEGIN(allowlist="...", blocklist="...")
# ... code to be monitored ...
anota_SYSCALL_END()
```
#### File System Shortcut: Use this to restrict file access to specific paths or permissions.
```Python
# Only allow read (r) and write (w) on the specific html folder
anota_SYSCALL.FILE(path='/var/www/html', options="rw")
```
Note: Access to any file outside this path will trigger a policy violation crash.

#### Network Shortcut: Use this to restrict network schemes or hosts.
```Python
# Block FTP and FILE schemes to prevent SSRF
anota_SYSCALL.NETWORK(blocklist_schemes=["ftp", "file"])
```
### Data Flow Tracking (anota_TAINT)
Use this to track "tainted" (sensitive or untrusted) data. ANOTA tracks the flow of this variable through the program.

Syntax:
```Python
anota_TAINT(variable, sanitization=[func_name], sink=[func_name])
```
variable: The data object to track (e.g., a password or user input).

sanitization: (Optional) List of functions that "clean" the data. If the variable passes through hash, for example, the taint is removed.

sink: (Optional) List of dangerous functions where tainted data should not go. Defaults to standard sinks like write() or network send.

###  Variable Watch (anota_WATCH)

Use this to monitor access to specific sensitive objects.

Syntax:
```Python
anota_WATCH(variable, option='rw')
```
variable: The object to monitor.

option='r': Report if the variable is read.

option='w': Report if the variable is modified (written to).

### Access Control (anota_ADMINONLY)
Use this to mark code regions or variables that require privileged access. This functions similarly to a security assertion or the EXECUTION.BLOCK concept.

Syntax:
```Python
# 1. Code Region Protection
if user.is_authenticated:
    anota_ADMINONLY() 
    # ... privileged code ...

# 2. Variable Protection
anota_ADMINONLY(variable, option='rw')
```
##  Common Protocols to Locate Vulnerabilities

A. Unrestricted File Upload
* Concept: Attackers upload dangerous files (e.g., .php, .exe) instead of intended media.
* Detection: Search for "upload" functionality. Look for existing file extension filtering functions (which might be weak).
* Annotation: Enforce the intended file type based on documentation.
* Example:
```Python
# From documentation: "User avatars must be JPEGs"
anota_SYSCALL.FILE(path='upload_folder', allowed_extension='jpeg')
```
* some framework documents
    * https://fastapi.tiangolo.com/tutorial/request-files/
    * https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
    * https://docs.djangoproject.com/en/5.0/topics/http/file-uploads/
    * https://gist.github.com/faisal-w/44694c2620d6ed692221

B. Path Traversal
* Concept: Attackers use ../ to access files outside the intended directory.
* Detection: Look for os.path.join, open(), or read() combined with user input. Look for route decorators like @app.get("/sample/{file_name}").
* Annotation: Restrict file system access to a specific constant directory.
* Example:
```Python
# Define the safe boundary
anota_SYSCALL.FILE(path=STATIC_DIR, options="r")
return open(os.path.join(STATIC_DIR, user_input))
```
C. Server-Side Request Forgery (SSRF)
* Concept: Attackers force the server to connect to internal services or local files.
* Detection: Look for string concatenation building URLs, or libraries like urllib.request, requests, or httpx.
* Annotation: Block dangerous schemes (file://, ftp://) and internal hosts (localhost, 127.0.0.1, 0.0.0.0).
* Example:
```Python
# Prevent access to local file system or internal metadata
anota_SYSCALL.NETWORK(blocklist_schemes=["file", "gopher"], blocklist_hosts=["169.254.169.254"])
```
* Also, if they craft html and send to remote user. HTML may be injected with local urls like `file:///etc/passwd` which is definitely not allowed.
* some related doc
    * https://www.starlette.io/responses/
    * https://en.wikipedia.org/wiki/Reserved_IP_addresses
    * https://www.digitalocean.com/community/tutorials/processing-incoming-request-data-in-flask

D. Information Exposure
* Concept: Sensitive data (passwords, tokens) is logged or returned in error messages.
* Detection:
    * Search for variable names: secret, token, id, cred, password, key.
    * Search for sink functions: log.debug, print, logger.info, raise.
* Regex Tip: (raise|log|print).*(secret|token|id|cred|password|key)
* Annotation: Taint the sensitive variable at its source.

Example:
```Python
api_key = get_credentials()
# Ensure this never hits a log file
anota_TAINT(api_key, sink=[logging.info, print, file_write])
```
E. Broken Access Control
* Concept: Unauthenticated users accessing admin functions.
* Detection: Identify authentication decorators (@auth.check, @login_required) or state variables (is_admin).
* Annotation: Place anota_ADMINONLY protection after the check is supposed to happen.
* Example:
```Python
@app.route('/admin_panel')
@requires_login
def admin_panel():
    anota_ADMINONLY() # Explicitly mark this scope as privileged
    # ... logic ...
```
* Some doc
            * https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login
            * https://stackoverflow.com/questions/67307265/where-to-put-depends-dependendies-for-authentication-in-fastapi
            * https://docs.djangoproject.com/en/5.0/topics/auth/default/

F. Deserialization of Untrusted Data
* Concept: Unsafe processing of serialization formats like Pickle or YAML.
* Detection: Search for pickle.load, yaml.load, or .pkl file processing.
* Annotation: Since deserialization can lead to arbitrary code execution, you can wrap the load function with system call blocks to prevent spawning shells.
* Example:
```Python
anota_SYSCALL_BEGIN(blocklist=["exec"])
data = pickle.load(user_input)
anota_SYSCALL_END()
```
