Dalfox Burp Standalone (Windows) - v1.2.7

New in this version:

1) Timeout and Rate Limit controls (Settings tab)
   - Timeout (seconds): mapped to Dalfox `--timeout <seconds>`.
     * 0 or empty = don't pass the flag (Dalfox default, usually 10s).
   - Delay between requests (ms): mapped to Dalfox `--delay <ms>`.
     * 0 or empty = no delay.
   - Values are persisted as Burp extension settings.

2) Safer issue URL handling
   - Burp issues now ALWAYS use the URL from Burp's own request (`helpers.analyzeRequest(base)`),
     not Dalfox's `data` field. This avoids "Invalid host:" errors.
   - The IHttpService is also taken from the base message.

3) Still only VERIFIED findings become issues
   - Dalfox JSONL lines with type "V" are turned into Burp issues.
   - Type "R" / others are shown in the Output tab but NOT added as issues.

4) No integration with Burp Active Scanner
   - The extension does NOT implement IScannerCheck anymore.
   - It does NOT hook into Burp's active scan/audit pipeline.

5) Modes of operation
   - Auto-scan (Proxy only):
       * When enabled, only incoming Proxy requests are sent to Dalfox.
   - Right-click single request:
       * "Scan this request with Dalfox" from Proxy/Repeater/Target/etc.
   - Target bulk scan:
       * Button: "Scan all Target site map (Dalfox)" in the Settings tab.

Build:
1) Put burp-extender-api.jar into lib/burp-extender-api.jar
2) mvn clean package
3) Load target/dalfox-burp-standalone-1.2.7-jar-with-dependencies.jar in Burp.
