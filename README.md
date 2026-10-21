# Secure REST API Development with CI/CD and CVE Vulnerability Analysis

**Author:** shishaoyi
**Student ID:** 23320103

---

## 1. Project and API Description
This project is a secure REST API built using Python (Flask). It utilizes SQLite for data storage via SQLAlchemy ORM. The API implements secure authentication using JWT and includes the following endpoints:

*   `POST /auth/login`: Accepts a JSON body with `username` and `password`. Upon successful authentication, it returns a JWT token.
<img width="415" height="221" alt="image" src="https://github.com/user-attachments/assets/fec53e90-a40a-4377-9e3c-025d4c094ba4" />
*   `GET /api/data`: A protected endpoint that returns a list of mock data. Requires a valid JWT in the `Authorization: Bearer <token>` header.
<img width="415" height="222" alt="image" src="https://github.com/user-attachments/assets/14372777-2232-421e-875a-9f827aca9769" />
*   `POST /api/register`: A supplementary endpoint to register a new user. Passwords are securely hashed before storage.
<img width="415" height="223" alt="image" src="https://github.com/user-attachments/assets/5700a738-d3e0-481a-8e2f-752c54e3ea97" />

---

## 2. Implemented Security Measures

### 2.1 Protection against SQL Injection (SQLi)
To prevent SQL injection, the application uses **Flask-SQLAlchemy (ORM)**. All database queries (such as `User.query.filter_by(...)`) are parameterized under the hood by the ORM. We strictly avoid string concatenation or f-strings when building SQL queries.

### 2.2 Protection against Cross-Site Scripting (XSS)
When returning user data, we ensure it is sanitized. While Flask returns JSON by default (which is safe), we use `markupsafe.escape` for any string data rendered in responses to neutralize any malicious HTML/JavaScript tags (e.g., `<script>alert(1)</script>`).

### 2.3 Protection against Broken Authentication
*   **Password Hashing:** Plaintext passwords are never stored. We use `bcrypt` with a unique salt per user to hash passwords before saving them to the database.
*   **JWT Authentication:** Upon successful login, the server issues a JWT signed with a secret key. We implemented a custom `@token_required` middleware decorator that intercepts requests to protected routes, verifies the token's signature, and ensures it hasn't expired before granting access.

---

## 3. CI/CD Pipeline and Security Scanners (SAST/SCA)
The CI/CD pipeline is configured using **GitHub Actions** (`.github/workflows/security.yml`). It triggers automatically on every push or pull request to the `main` branch.

*   **SAST (Static Application Security Testing):** We use **Bandit** to scan the Python source code for common security issues (e.g., hardcoded secrets, use of unsafe functions).
*   **SCA (Software Composition Analysis):** We use **Safety** to check `requirements.txt` and installed dependencies against a database of known vulnerabilities.

### Screenshots of SAST/SCA Reports
<img width="414" height="201" alt="image" src="https://github.com/user-attachments/assets/a4b1aa44-8640-4b3e-8410-020cf9fad707" />

*(Link to the successful pipeline run: 【在此处填入你 GitHub Actions 运行的网页链接】)*

---

## 4. Real CVE Vulnerability Analysis: CVE-2015-5254

### 4.1 Vulnerability Name and Description
*   **CVE ID:** CVE-2015-5254
*   **Component:** Apache ActiveMQ
*   **Description:** This is a critical Remote Code Execution (RCE) vulnerability caused by insecure deserialization. ActiveMQ versions prior to 5.13.0 do not restrict classes that can be deserialized, allowing attackers to send malicious serialized `ObjectMessage` payloads to execute arbitrary code on the server.

### 4.2 Reproduction Steps
The vulnerable environment was launched using Vulhub (`vulhub/activemq/CVE-2015-5254`) with version `5.11.1`. The `jmet` tool was used to generate the payload.

**Step 1: Send the malicious payload**
We sent a payload to execute `touch /tmp/success` via the ROME gadget chain to the ActiveMQ broker port (mapped to 16161).

java -jar jmet-0.1.0-all.jar -Q event -I ActiveMQ -s -Y "touch /tmp/success" -Yp ROME 127.0.0.1 16161

【在此处插入 jmet 终端发送成功 (带绿字) 的截图】

Step 2: Trigger the vulnerability
Navigated to the ActiveMQ Web Console (http://127.0.0.1:8161/admin/), clicked on the event queue, and clicked on the Message ID to trigger deserialization.
【在此处插入 网页端显示 Message ID 列表或者报错 Forbidden class 的截图】

Step 3: Verify Exploitation
Entered the running container and checked for the file created by the command.
docker exec -it <container_id> /bin/bash
ls -la /tmp/success

【在此处插入 5.11.1 容器内显示 /tmp/success 文件存在的截图】

4.3 Root Cause Analysis
The root cause is that the ActiveMQ Broker blindly accepts and deserializes Java objects from incoming JMS messages (specifically ObjectMessage) without verifying if the classes being deserialized are safe. By crafting a message containing a malicious "gadget chain" (like the ROME library payload), the deserialization process triggers unexpected method executions, ultimately leading to RCE.

4.4 Applied Fix
The most effective fix is to upgrade ActiveMQ to a patched version where class filtering (allowlist/blocklist) is enforced.
We modified the docker-compose.yml file to use the secure version 5.16.5 instead of the vulnerable 5.11.1.

Changes made in 'docker-compose.yml':
services:
  activemq:
    # image: vulhub/activemq:5.11.1  <-- Vulnerable version
    image: vulhub/activemq:5.16.5     # <-- Patched version

4.5 Proof of Vulnerability Elimination
After upgrading to 5.16.5, we restarted the environment and repeated the exact same attack steps. The broker's security mechanism successfully intercepted and blocked the deserialization of the malicious class.

Verification in the Web Console:
The web console threw an exception stating Forbidden class, indicating the payload was blocked.
【在此处插入 网页端显示 Forbidden class 的截图（就是你发我的那张）】

Verification in the Container:
Entered the new container and checked for the file.

bash
ls -la /tmp/success
The command returned "No such file or directory", proving the RCE was successfully prevented.
【在此处插入 5.16.5 容器内显示 No such file or directory 的截图】

(Note: Regression testing was performed by ensuring the ActiveMQ Web Console and normal queue processing still functioned correctly after the upgrade.)
