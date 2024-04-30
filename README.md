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

<p>5. To check if it's working this url should say "Hello"</p>

```
localhost:[port]/api
```

<h2>💻 Built with</h2>

Technologies used in the project:

*   <a href="https://spring.io/" target="_blank" rel="noreferrer"> <img src="https://www.vectorlogo.zone/logos/springio/springio-icon.svg" alt="Spring boot" width="20" height="20"/> </a>
*   <a href="https://www.osquery.io" target="_blank" rel="noreferrer"> <img src="https://www.osquery.io/favicons/favicon.ico" alt="OSQuery" width="20" height="20"/> </a>