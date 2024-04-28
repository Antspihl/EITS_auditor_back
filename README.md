<h1 align="center" id="title">E-ITS auditor backend</h1>

<p id="description">Backend for automatic audit of the implementation of E-ITS SYS measures in the environment of a family doctor's center</p>

<h2>🛠️ Installation Steps:</h2>

<p>1. Install OSQuery</p>

https://www.osquery.io/downloads/official

<p>2. Make sure system variable "Path" has value:</p>

```
C:\Program Files\osquery
```

<p>3. Download EITS_auditor_back-1.0 from the project</p>

```
init/EITS_auditor_back-1.0
```

<p>4. Run the .jar with this command:</p>

*   Replace [path] with the path to the .jar.
*   Replace [port] with the desired port it should run on.

```bash
java -jar "[path]" --server.port=[port]
```

<p>5. To check if working this url should say "Hello"</p>

```
localhost:[port]/api
```

<h2>💻 Built with</h2>

Technologies used in the project:

*   Spring Boot
*   OSQuery