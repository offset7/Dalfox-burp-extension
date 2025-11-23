package burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IScanIssue;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.ITab;
import burp.IHttpListener;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;

import org.json.JSONObject;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.Box;
import javax.swing.SwingUtilities;
import javax.swing.JTabbedPane;
import javax.swing.JEditorPane;
import javax.swing.JCheckBox;
import javax.swing.JMenuItem;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DalfoxStandaloneExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

    private static final String SETTING_EXE_PATH = "dalfoxExePath";
    private static final String SETTING_AUTO_SCAN = "dalfoxAutoScanAll";
    private static final String SETTING_TIMEOUT = "dalfoxTimeoutSeconds";
    private static final String SETTING_DELAY = "dalfoxDelayMs";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private File dalfoxBinary;
    private volatile boolean autoScanAllRequests = false;

    private int timeoutSeconds = 0; // 0 = use Dalfox default
    private int delayMs = 0;        // 0 = no delay

    private JPanel mainPanel;
    private JTextField exePathField;
    private JTextField timeoutField;
    private JTextField delayField;
    private JLabel statusLabel;
    private JTextArea outputArea;
    private JCheckBox autoScanCheckBox;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Dalfox Standalone XSS Scanner (Windows)");

        buildUi();
        callbacks.addSuiteTab(this);

        // Load saved Dalfox path
        String savedPath = callbacks.loadExtensionSetting(SETTING_EXE_PATH);
        if (savedPath != null && !savedPath.trim().isEmpty()) {
            File f = new File(savedPath.trim());
            if (f.exists() && f.isFile()) {
                dalfoxBinary = f;
                exePathField.setText(f.getAbsolutePath());
                setStatus("Using dalfox from: " + f.getAbsolutePath());
            } else {
                setStatus("Saved dalfox path not found. Please configure a valid path.");
            }
        } else {
            setStatus("Please configure dalfox executable path in Settings.");
        }

        // Load auto-scan flag
        String autoScanSetting = callbacks.loadExtensionSetting(SETTING_AUTO_SCAN);
        if ("true".equalsIgnoreCase(autoScanSetting)) {
            autoScanAllRequests = true;
            if (autoScanCheckBox != null) {
                autoScanCheckBox.setSelected(true);
            }
        }

        // Load timeout
        String savedTimeout = callbacks.loadExtensionSetting(SETTING_TIMEOUT);
        if (savedTimeout != null && !savedTimeout.trim().isEmpty()) {
            try {
                timeoutSeconds = Integer.parseInt(savedTimeout.trim());
                if (timeoutField != null) {
                    timeoutField.setText(String.valueOf(timeoutSeconds));
                }
            } catch (NumberFormatException e) {
                timeoutSeconds = 0;
            }
        }

        // Load delay
        String savedDelay = callbacks.loadExtensionSetting(SETTING_DELAY);
        if (savedDelay != null && !savedDelay.trim().isEmpty()) {
            try {
                delayMs = Integer.parseInt(savedDelay.trim());
                if (delayField != null) {
                    delayField.setText(String.valueOf(delayMs));
                }
            } catch (NumberFormatException e) {
                delayMs = 0;
            }
        }

        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public String getTabCaption() {
        return "dalfox";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    private void buildUi() {
        mainPanel = new JPanel(new BorderLayout());

        JTabbedPane tabs = new JTabbedPane();

        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel settingsInner = new JPanel();
        settingsInner.setLayout(new BoxLayout(settingsInner, BoxLayout.Y_AXIS));
        settingsInner.setBorder(BorderFactory.createTitledBorder("Settings"));

        // ===== Dalfox path row =====
        JPanel pathRow = new JPanel();
        pathRow.setLayout(new BoxLayout(pathRow, BoxLayout.X_AXIS));

        JLabel exeLabel = new JLabel("dalfox executable path: ");
        exePathField = new JTextField();
        exePathField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 25));

        JButton browseButton = new JButton("Browse...");
        browseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                int result = chooser.showOpenDialog(mainPanel);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File f = chooser.getSelectedFile();
                    exePathField.setText(f.getAbsolutePath());
                }
            }
        });

        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Save dalfox path
                String path = exePathField.getText().trim();
                if (path.isEmpty()) {
                    dalfoxBinary = null;
                    callbacks.saveExtensionSetting(SETTING_EXE_PATH, "");
                    setStatus("Cleared dalfox path. Extension will not run Dalfox until a valid path is set.");
                } else {
                    File f = new File(path);
                    if (!f.exists() || !f.isFile()) {
                        setStatus("Invalid path. File does not exist: " + path);
                        callbacks.printError("[Dalfox] Invalid dalfox path: " + path);
                        return;
                    }
                    dalfoxBinary = f;
                    callbacks.saveExtensionSetting(SETTING_EXE_PATH, f.getAbsolutePath());
                    setStatus("Saved dalfox path: " + f.getAbsolutePath());
                }

                // Save timeout
                String tText = timeoutField.getText().trim();
                if (tText.isEmpty()) {
                    timeoutSeconds = 0;
                    callbacks.saveExtensionSetting(SETTING_TIMEOUT, "");
                } else {
                    try {
                        int t = Integer.parseInt(tText);
                        if (t < 0) {
                            setStatus("Timeout must be >= 0");
                            return;
                        }
                        timeoutSeconds = t;
                        callbacks.saveExtensionSetting(SETTING_TIMEOUT, String.valueOf(t));
                    } catch (NumberFormatException ex) {
                        setStatus("Invalid timeout, must be an integer (seconds).");
                        return;
                    }
                }

                // Save delay
                String dText = delayField.getText().trim();
                if (dText.isEmpty()) {
                    delayMs = 0;
                    callbacks.saveExtensionSetting(SETTING_DELAY, "");
                } else {
                    try {
                        int d = Integer.parseInt(dText);
                        if (d < 0) {
                            setStatus("Delay must be >= 0");
                            return;
                        }
                        delayMs = d;
                        callbacks.saveExtensionSetting(SETTING_DELAY, String.valueOf(d));
                    } catch (NumberFormatException ex) {
                        setStatus("Invalid delay, must be an integer (ms).");
                        return;
                    }
                }

                appendOutputLine("[Dalfox] Saved configuration. Timeout=" + timeoutSeconds +
                                 "s, Delay=" + delayMs + "ms");
            }
        });

        pathRow.add(exeLabel);
        pathRow.add(Box.createRigidArea(new Dimension(5, 0)));
        pathRow.add(exePathField);
        pathRow.add(Box.createRigidArea(new Dimension(5, 0)));
        pathRow.add(browseButton);
        pathRow.add(Box.createRigidArea(new Dimension(5, 0)));
        pathRow.add(saveButton);

        // ===== Timeout row =====
        JPanel timeoutRow = new JPanel();
        timeoutRow.setLayout(new BoxLayout(timeoutRow, BoxLayout.X_AXIS));
        JLabel timeoutLabel = new JLabel("Timeout (seconds, 0 = Dalfox default): ");
        timeoutField = new JTextField();
        timeoutField.setMaximumSize(new Dimension(120, 25));
        timeoutRow.add(timeoutLabel);
        timeoutRow.add(Box.createRigidArea(new Dimension(5, 0)));
        timeoutRow.add(timeoutField);

        // ===== Delay row =====
        JPanel delayRow = new JPanel();
        delayRow.setLayout(new BoxLayout(delayRow, BoxLayout.X_AXIS));
        JLabel delayLabel = new JLabel("Delay between requests (ms, 0 = no delay): ");
        delayField = new JTextField();
        delayField.setMaximumSize(new Dimension(120, 25));
        delayRow.add(delayLabel);
        delayRow.add(Box.createRigidArea(new Dimension(5, 0)));
        delayRow.add(delayField);

        statusLabel = new JLabel("Status: not initialized");
        statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));

        autoScanCheckBox = new JCheckBox("Automatically run Dalfox on incoming Proxy requests only");
        autoScanCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        autoScanCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                autoScanAllRequests = autoScanCheckBox.isSelected();
                callbacks.saveExtensionSetting(SETTING_AUTO_SCAN, autoScanAllRequests ? "true" : "false");
                appendOutputLine("[Dalfox] Auto-scan on Proxy requests set to: " + autoScanAllRequests);
            }
        });

        JButton scanTargetButton = new JButton("Scan all Target site map (Dalfox)");
        scanTargetButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        scanTargetButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                runTargetSiteMapScan();
            }
        });

        settingsInner.add(pathRow);
        settingsInner.add(Box.createRigidArea(new Dimension(0, 5)));
        settingsInner.add(timeoutRow);
        settingsInner.add(Box.createRigidArea(new Dimension(0, 5)));
        settingsInner.add(delayRow);
        settingsInner.add(Box.createRigidArea(new Dimension(10, 10)));
        settingsInner.add(statusLabel);
        settingsInner.add(Box.createRigidArea(new Dimension(10, 10)));
        settingsInner.add(autoScanCheckBox);
        settingsInner.add(Box.createRigidArea(new Dimension(10, 10)));
        settingsInner.add(scanTargetButton);

        settingsPanel.add(settingsInner);

        // ===== About tab =====
        JPanel aboutPanel = new JPanel(new BorderLayout());
        aboutPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel aboutInner = new JPanel(new BorderLayout());
        aboutInner.setBorder(BorderFactory.createTitledBorder("About"));

        String aboutHtml =
            "<html>" +
            "<head>" +
            "<style>" +
            "body { font-family: sans-serif; font-size: 11px; }" +
            "h1 { font-size: 14px; margin-bottom: 4px; }" +
            "a { text-decoration: none; }" +
            "</style>" +
            "</head>" +
            "<body>" +
            "<h1>Dalfox Burp Standalone Extension</h1>" +
            "<p><b>Author:</b> Ahmed Atef</p>" +
            "<p><b>Website:</b> <a href='https://offset7.com'>https://offset7.com</a></p>" +
            "<p><b>Personal Site:</b> <a href='https://ahmadatef.net/'>https://ahmadatef.net/</a></p>" +
            "<p><b>LinkedIn:</b> <a href='https://www.linkedin.com/in/ahmed-pentest/'>"
                + "https://www.linkedin.com/in/ahmed-pentest/</a></p>" +
            "<p>This extension calls an external Dalfox (XSS scanner) executable.<br>" +
            "It can run via a single right-click menu item, automatically on incoming Proxy requests, or on the entire Target site map.</p>" +
            "</body></html>";

        JEditorPane aboutPane = new JEditorPane();
        aboutPane.setContentType("text/html");
        aboutPane.setText(aboutHtml);
        aboutPane.setEditable(false);
        aboutPane.setOpaque(false);

        JScrollPane aboutScroll = new JScrollPane(aboutPane);
        aboutInner.add(aboutScroll, BorderLayout.CENTER);
        aboutPanel.add(aboutInner, BorderLayout.CENTER);

        // ===== Output tab =====
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel outputInner = new JPanel(new BorderLayout());
        outputInner.setBorder(BorderFactory.createTitledBorder("Scan Output (raw)"));

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setLineWrap(false);
        outputArea.setFont(new Font("Consolas", Font.PLAIN, 12));

        JScrollPane scroll = new JScrollPane(outputArea);
        outputInner.add(scroll, BorderLayout.CENTER);
        outputPanel.add(outputInner, BorderLayout.CENTER);

        tabs.addTab("Settings", settingsPanel);
        tabs.addTab("About", aboutPanel);
        tabs.addTab("Output", outputPanel);

        mainPanel.add(tabs, BorderLayout.CENTER);
    }

    private void setStatus(final String text) {
        if (statusLabel == null) return;
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                statusLabel.setText("Status: " + text);
            }
        });
    }

    private void appendOutputLine(final String text) {
        if (outputArea == null) return;
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                outputArea.append(text + "\n");
                outputArea.setCaretPosition(outputArea.getDocument().getLength());
            }
        });
    }

    // =========================
    // IHttpListener (auto-scan only Proxy requests)
    // =========================

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            return;
        }
        if (!autoScanAllRequests) {
            return;
        }
        if (!isDalfoxReady()) {
            return;
        }
        // Only scan incoming Proxy requests
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return;
        }

        try {
            IRequestInfo ri = helpers.analyzeRequest(messageInfo);
            URL url = ri.getUrl();
            final String targetUrl = url.toString();
            final String rawRequest = helpers.bytesToString(messageInfo.getRequest());
            final IHttpRequestResponse baseMessage = messageInfo;

            appendOutputLine("=== Dalfox Auto-Scan (Proxy) queued for: " + targetUrl + " ===");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        List<DalfoxFinding> findings = runDalfoxRawFile(dalfoxBinary, rawRequest);
                        appendOutputLine("=== Dalfox Auto-Scan (Proxy) finished for: " + targetUrl +
                                         " (verified findings: " + findings.size() + ") ===");

                        for (DalfoxFinding f : findings) {
                            IHttpRequestResponse msg = buildHttpMessageForFinding(baseMessage, f);
                            IScanIssue issue = new DalfoxIssue(
                                    baseMessage,
                                    new IHttpRequestResponse[]{ msg },
                                    f
                            );
                            callbacks.addScanIssue(issue);
                        }
                    } catch (Exception ex) {
                        callbacks.printError("[Dalfox] Error during auto-scan (Proxy): " + ex.getMessage());
                        appendOutputLine("[Dalfox] Error during auto-scan (Proxy) for " + targetUrl + ": " + ex.getMessage());
                    }
                }
            }, "Dalfox-Autoscan-Proxy-" + System.currentTimeMillis()).start();

        } catch (Exception e) {
            callbacks.printError("[Dalfox] processHttpMessage error: " + e.getMessage());
        }
    }

    // =========================
    // Target site map bulk scan
    // =========================

    private void runTargetSiteMapScan() {
        if (!isDalfoxReady()) {
            appendOutputLine("[Dalfox] Cannot scan Target: no valid dalfox path configured.");
            return;
        }

        appendOutputLine("=== Dalfox: starting scan of entire Target site map ===");

        IHttpRequestResponse[] items = callbacks.getSiteMap(null);
        if (items == null || items.length == 0) {
            appendOutputLine("[Dalfox] Target site map is empty.");
            return;
        }

        new Thread(new Runnable() {
            @Override
            public void run() {
                int total = items.length;
                int index = 0;
                for (IHttpRequestResponse item : items) {
                    index++;
                    try {
                        IRequestInfo ri = helpers.analyzeRequest(item);
                        URL url = ri.getUrl();
                        String targetUrl = url.toString();
                        String rawRequest = helpers.bytesToString(item.getRequest());

                        appendOutputLine("[Dalfox] [Target scan] (" + index + "/" + total + ") " + targetUrl);

                        List<DalfoxFinding> findings = runDalfoxRawFile(dalfoxBinary, rawRequest);

                        for (DalfoxFinding f : findings) {
                            IHttpRequestResponse msg = buildHttpMessageForFinding(item, f);
                            IScanIssue issue = new DalfoxIssue(
                                    item,
                                    new IHttpRequestResponse[]{ msg },
                                    f
                            );
                            callbacks.addScanIssue(issue);
                        }
                    } catch (Exception ex) {
                        callbacks.printError("[Dalfox] Error during Target scan: " + ex.getMessage());
                        appendOutputLine("[Dalfox] Error during Target scan: " + ex.getMessage());
                    }
                }
                appendOutputLine("=== Dalfox: finished scan of Target site map ===");
            }
        }, "Dalfox-TargetScan-" + System.currentTimeMillis()).start();
    }

    // =========================
    // IContextMenuFactory ("Scan this request with Dalfox")
    // =========================

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();

        JMenuItem singleScanItem = new JMenuItem("Scan this request with Dalfox");
        singleScanItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!isDalfoxReady()) {
                    appendOutputLine("[Dalfox] Cannot scan: no valid dalfox path configured.");
                    return;
                }

                IHttpRequestResponse[] selected = invocation.getSelectedMessages();
                if (selected == null || selected.length == 0) {
                    appendOutputLine("[Dalfox] No request selected for single scan.");
                    return;
                }

                IHttpRequestResponse base = selected[0];

                try {
                    IRequestInfo ri = helpers.analyzeRequest(base);
                    URL url = ri.getUrl();
                    String targetUrl = url.toString();
                    String rawRequest = helpers.bytesToString(base.getRequest());

                    appendOutputLine("=== Dalfox Single-Request Scan for: " + targetUrl + " ===");

                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                List<DalfoxFinding> findings = runDalfoxRawFile(dalfoxBinary, rawRequest);
                                appendOutputLine("=== Dalfox Single-Request Scan finished for: " + targetUrl +
                                                 " (verified findings: " + findings.size() + ") ===");

                                for (DalfoxFinding f : findings) {
                                    IHttpRequestResponse msg = buildHttpMessageForFinding(base, f);
                                    IScanIssue issue = new DalfoxIssue(
                                            base,
                                            new IHttpRequestResponse[]{ msg },
                                            f
                                    );
                                    callbacks.addScanIssue(issue);
                                }
                            } catch (Exception ex) {
                                callbacks.printError("[Dalfox] Error during single-request scan: " + ex.getMessage());
                                appendOutputLine("[Dalfox] Error during single-request scan for " + targetUrl + ": " + ex.getMessage());
                            }
                        }
                    }, "Dalfox-SingleScan-" + System.currentTimeMillis()).start();

                } catch (Exception ex) {
                    callbacks.printError("[Dalfox] Error preparing single-request scan: " + ex.getMessage());
                }
            }
        });

        items.add(singleScanItem);
        return items;
    }

    // =========================
    // Dalfox integration
    // =========================

    private boolean isDalfoxReady() {
        return dalfoxBinary != null && dalfoxBinary.exists() && dalfoxBinary.isFile();
    }

    private List<DalfoxFinding> runDalfoxRawFile(File dalfox, String rawRequest)
            throws IOException, InterruptedException {

        List<DalfoxFinding> findings = new ArrayList<>();

        File tmp = File.createTempFile("dalfox-raw-", ".txt");
        try (FileOutputStream fos = new FileOutputStream(tmp)) {
            fos.write(rawRequest.getBytes(StandardCharsets.ISO_8859_1));
        }

        List<String> cmd = new ArrayList<>();
        cmd.add(dalfox.getAbsolutePath());
        cmd.add("file");
        cmd.add(tmp.getAbsolutePath());
        cmd.add("--rawdata");
        cmd.add("--http");
        cmd.add("--format");
        cmd.add("jsonl");
        cmd.add("--no-color");
        cmd.add("--no-spinner");
        cmd.add("--silence");

        // Apply timeout and delay if configured
        if (timeoutSeconds > 0) {
            cmd.add("--timeout");
            cmd.add(String.valueOf(timeoutSeconds));
        }
        if (delayMs > 0) {
            cmd.add("--delay");
            cmd.add(String.valueOf(delayMs));
        }

        appendOutputLine("[Dalfox] Executing: " + String.join(" ", cmd));

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                final String rawLine = line;
                appendOutputLine(rawLine);

                String trimmed = rawLine.trim();
                if (trimmed.isEmpty()) continue;
                if (!trimmed.startsWith("{")) continue;

                try {
                    JSONObject o = new JSONObject(trimmed);
                    DalfoxFinding f = new DalfoxFinding();
                    f.type = o.optString("type"); // R, V, etc.
                    f.injectType = o.optString("inject_type");
                    f.pocType = o.optString("poc_type");
                    f.method = o.optString("method");
                    f.data = o.optString("data");
                    f.param = o.optString("param");
                    f.payload = o.optString("payload");
                    f.evidence = o.optString("evidence");
                    f.cwe = o.optString("cwe");
                    f.severity = o.optString("severity");
                    f.rawHttpRequest = o.optString("raw_http_request");
                    f.rawHttpResponse = o.optString("raw_http_response");

                    // Only keep verified findings (type == "V") as Burp issues
                    if ("V".equalsIgnoreCase(f.type)) {
                        findings.add(f);
                    }
                } catch (Exception ex) {
                    callbacks.printError("[Dalfox] JSON parse error: " + ex.getMessage());
                }
            }
        } finally {
            if (tmp.exists()) {
                tmp.delete();
            }
        }

        int exitCode = p.waitFor();
        if (exitCode != 0) {
            callbacks.printError("[Dalfox] dalfox exited with code " + exitCode);
            appendOutputLine("[Dalfox] dalfox exited with code " + exitCode);
        }

        return findings;
    }

    private IHttpRequestResponse buildHttpMessageForFinding(IHttpRequestResponse base, DalfoxFinding finding) {
        try {
            IHttpRequestResponse persisted = callbacks.saveBuffersToTempFiles(base);

            if (finding.rawHttpRequest != null && !finding.rawHttpRequest.isEmpty()) {
                byte[] req = helpers.stringToBytes(finding.rawHttpRequest);
                persisted.setRequest(req);
            }
            if (finding.rawHttpResponse != null && !finding.rawHttpResponse.isEmpty()) {
                byte[] resp = helpers.stringToBytes(finding.rawHttpResponse);
                persisted.setResponse(resp);
            }

            return persisted;
        } catch (Exception e) {
            callbacks.printError("[Dalfox] Error building HTTP message for finding: " + e.getMessage());
            return base;
        }
    }

    private static class DalfoxFinding {
        String type;
        String injectType;
        String pocType;
        String method;
        String data;
        String param;
        String payload;
        String evidence;
        String cwe;
        String severity;
        String rawHttpRequest;
        String rawHttpResponse;
    }

    private class DalfoxIssue implements IScanIssue {

        private final IHttpService httpService;
        private final URL url;
        private final IHttpRequestResponse[] messages;
        private final DalfoxFinding finding;

        DalfoxIssue(IHttpRequestResponse baseMessage,
                    IHttpRequestResponse[] messages, DalfoxFinding finding) {
            IRequestInfo ri = helpers.analyzeRequest(baseMessage);
            this.url = ri.getUrl(); // Always use Burp's URL (safe host)
            this.httpService = baseMessage.getHttpService();
            this.messages = messages;
            this.finding = finding;
        }

        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return "Dalfox XSS (" + (finding.severity == null ? "UNKNOWN" : finding.severity.toUpperCase()) + ")";
        }

        @Override
        public int getIssueType() {
            return 0;
        }

        @Override
        public String getSeverity() {
            String s = finding.severity == null ? "" : finding.severity.toLowerCase();
            switch (s) {
                case "high": return "High";
                case "medium": return "Medium";
                case "low": return "Low";
                default: return "Information";
            }
        }

        @Override
        public String getConfidence() {
            return "Firm";
        }

        @Override
        public String getIssueBackground() {
            return "This issue was discovered by Dalfox (XSS scanner), invoked by a Burp Suite extension. "
                 + "Dalfox identified a potential cross-site scripting (XSS) vulnerability.";
        }

        @Override
        public String getRemediationBackground() {
            return "Apply proper output encoding and input validation. "
                 + "Use context-appropriate escaping and consider enforcing a Content Security Policy (CSP).";
        }

        @Override
        public String getIssueDetail() {
            StringBuilder sb = new StringBuilder();
            sb.append("Dalfox reported a verified XSS finding (type=V):<br><br>");
            sb.append("<b>Type:</b> ").append(escape(finding.type)).append("<br>");
            sb.append("<b>PoC Type:</b> ").append(escape(finding.pocType)).append("<br>");
            sb.append("<b>Injection Type:</b> ").append(escape(finding.injectType)).append("<br>");
            sb.append("<b>HTTP Method:</b> ").append(escape(finding.method)).append("<br>");
            sb.append("<b>Parameter:</b> ").append(escape(finding.param)).append("<br>");
            sb.append("<b>Payload:</b> <code>").append(escape(finding.payload)).append("</code><br>");
            sb.append("<b>CWE:</b> ").append(escape(finding.cwe)).append("<br>");
            sb.append("<b>Evidence:</b><br><pre>").append(escape(finding.evidence)).append("</pre><br>");

            if (finding.rawHttpRequest != null && !finding.rawHttpRequest.isEmpty()) {
                sb.append("<b>Raw Request (from Dalfox):</b><br><pre>")
                  .append(escape(finding.rawHttpRequest)).append("</pre><br>");
            }
            if (finding.rawHttpResponse != null && !finding.rawHttpResponse.isEmpty()) {
                sb.append("<b>Raw Response (from Dalfox):</b><br><pre>")
                  .append(escape(finding.rawHttpResponse)).append("</pre><br>");
            }

            return sb.toString();
        }

        @Override
        public String getRemediationDetail() {
            return null;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return messages;
        }

        @Override
        public IHttpService getHttpService() {
            return httpService;
        }

        private String escape(String s) {
            if (s == null) return "";
            return s.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;");
        }
    }
}
