# System.Net.Http.DigestAuthMessageHandler

Features

* Authentication via Digest
* Cache the credential token for subsequent requests
* Automatically renew the credential token

Usage

```csharp
using System.Net.Http;

var clientHandler = new HttpClientHandler(digestAuthHandler);
var digestAuthHandler = new DigestAuthMessageHandler(clientHandler, "<username>", "<password>");
var client = new HttpClient(digestAuthHandler);
```
