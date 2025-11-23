

## Dalfox Burp Extension



`dalfox-burp-extension` is a lightweight standalone utility that integrates \*\*Dalfox\*\* (XSS scanner) with \*\*Burp Suite\*\* without requiring any complex extension development. It’s designed to be portable, simple to use, and easy to plug into your existing penetration testing workflow.



This tool allows you to pipe Burp traffic or exported HTTP requests directly into Dalfox, automating XSS scanning and improving testing efficiency while maintaining your usual Burp workflow.



---



## 🚀 Features



- \*\*Standalone Integration\*\*  

&nbsp; No custom Burp plugins required—run it alongside Burp Suite.



- \*\*Simple Setup\*\*  

&nbsp; Point the tool to Dalfox and Burp output, and start scanning.



- \*\*Supports Burp History / Exports\*\*  

&nbsp; Works with saved HTTP requests, proxy logs, and defined scopes.



- \*\*Clean Output\*\*  

&nbsp; JSON and plain-text output options for easy parsing or reporting.



- \*\*Script-Friendly\*\*  

&nbsp; Integrates smoothly with CI/CD, automation scripts, and custom toolchains.



---



## 📌 Use Cases



- Automatically sending Burp-captured requests to Dalfox for XSS scanning.

- Re-scanning specific endpoints manually selected from Burp Suite.

- Integrating Dalfox into manual pentesting workflows without changing Burp configuration.

- Lightweight alternative to traditional Burp extensions.



---





## ⚠️ Required Dependency: Dalfox

`dalfox-burp-standalone` does \*\*not\*\* bundle the Dalfox scanner itself.

You \*\*must download the Dalfox binary manually\*\* from the official Dalfox release page:
👉 \*\*https://github.com/hahwul/dalfox/releases/



After downloading:
- Place the Dalfox binary in your `$PATH`, \*\*or\*\*
- Provide its path when running this tool.

