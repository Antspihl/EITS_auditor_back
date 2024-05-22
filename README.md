<p align="center"><img 
src="https://socialify.git.ci/Antspihl/EITS_auditor_back/image?description=1&font=Bitter&language=1&name=1&pattern=Circuit%20Board&theme=Auto" 
alt="project-image"></p>

<h2>📝 Disclaimer:</h2>

* Meant to be used with the <a href="https://github.com/Antspihl/EITS_auditor_front">EITS_auditor_front</a> project.
* Communicates only in the local network.
* Doesn't store any data or send it to any external server.
* Because it communicates via HTTP at the moment, it's recommended to set rules in place to only allow communication between the front and back-end servers but it's not necessary.

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

* Replace [path] with the path to the .jar.
* Replace [port] with the desired port it should run on.

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