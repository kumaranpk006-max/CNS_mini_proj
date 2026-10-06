package com.phishingdetector;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

/**
 * MainGUI
 * Redesigned security operations center interface matching the reference layout.
 * Features:
 * - Professional title and subtitle header with real-time status indicator
 * - Custom styled gradient action toolbar
 * - Large, prominent security terminal console for structured analysis output
 * - Safe simulation mode, feature inspector, and security log viewer
 */
public class MainGUI extends JFrame {

    private JTextField urlInputField;
    private JTextArea outputArea;
    private JLabel systemStatusLabel;

    private JButton analyzeButton;
    private JButton simulationButton;
    private JButton viewFeaturesButton;
    private JButton viewLogButton;
    private JButton clearButton;

    private PredictionResult lastResult;

    public MainGUI() {
        setTitle("AI-Based Phishing URL Detection System");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1020, 720);
        setMinimumSize(new Dimension(880, 600));
        setLocationRelativeTo(null); // Center on screen

        initUI();
    }

    private void initUI() {
        JPanel mainPanel = new JPanel(new BorderLayout(10, 12));
        mainPanel.setBackground(new Color(250, 250, 250));
        mainPanel.setBorder(new EmptyBorder(18, 22, 18, 22));

        // 1. TOP HEADER (Matches reference: Title + Subtitle on Left, Status on Right)
        mainPanel.add(createTopHeaderPanel(), BorderLayout.NORTH);

        // 2. CENTER PANEL (Input Row + Button Toolbar + Large Output Terminal)
        JPanel centerPanel = new JPanel(new BorderLayout(10, 10));
        centerPanel.setBackground(new Color(250, 250, 250));

        // Controls container (Input bar + Button row)
        JPanel controlsContainer = new JPanel();
        controlsContainer.setLayout(new BoxLayout(controlsContainer, BoxLayout.Y_AXIS));
        controlsContainer.setBackground(new Color(250, 250, 250));

        controlsContainer.add(createInputRow());
        controlsContainer.add(Box.createVerticalStrut(8));
        controlsContainer.add(createButtonToolbar());

        centerPanel.add(controlsContainer, BorderLayout.NORTH);

        // Large Output Terminal
        centerPanel.add(createTerminalOutputPanel(), BorderLayout.CENTER);

        mainPanel.add(centerPanel, BorderLayout.CENTER);

        setContentPane(mainPanel);

        // Print initial welcome message in output terminal
        printSystemReadyBanner();

        // Warm up ML model in background thread
        warmupModelInBackground();
    }

    private JPanel createTopHeaderPanel() {
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(250, 250, 250));
        headerPanel.setBorder(new EmptyBorder(0, 4, 6, 4));

        // Left Title & Subtitle
        JPanel titlePanel = new JPanel(new GridLayout(2, 1, 2, 2));
        titlePanel.setBackground(new Color(250, 250, 250));

        JLabel titleLabel = new JLabel("AI-BASED PHISHING URL DETECTION SYSTEM");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        titleLabel.setForeground(new Color(30, 35, 42));

        JLabel subtitleLabel = new JLabel("Java-Based Machine Learning URL Security Monitoring");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        subtitleLabel.setForeground(new Color(110, 115, 125));

        titlePanel.add(titleLabel);
        titlePanel.add(subtitleLabel);

        // Right Status Indicator
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 10));
        statusPanel.setBackground(new Color(250, 250, 250));

        systemStatusLabel = new JLabel("● SYSTEM READY");
        systemStatusLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        systemStatusLabel.setForeground(new Color(35, 40, 50));

        statusPanel.add(systemStatusLabel);

        headerPanel.add(titlePanel, BorderLayout.WEST);
        headerPanel.add(statusPanel, BorderLayout.EAST);

        return headerPanel;
    }

    private JPanel createInputRow() {
        JPanel inputPanel = new JPanel(new BorderLayout(10, 0));
        inputPanel.setBackground(new Color(250, 250, 250));
        inputPanel.setBorder(new EmptyBorder(4, 2, 4, 2));

        JLabel promptLabel = new JLabel("Target Website URL:");
        promptLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        promptLabel.setForeground(new Color(40, 45, 55));

        urlInputField = new JTextField("https://www.google.com");
        urlInputField.setFont(new Font("Consolas", Font.PLAIN, 14));
        urlInputField.setPreferredSize(new Dimension(0, 34));
        urlInputField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(185, 195, 205), 1),
                new EmptyBorder(4, 8, 4, 8)
        ));
        urlInputField.addActionListener(e -> analyzeURLAction());

        inputPanel.add(promptLabel, BorderLayout.WEST);
        inputPanel.add(urlInputField, BorderLayout.CENTER);

        return inputPanel;
    }

    private JPanel createButtonToolbar() {
        JPanel toolbar = new JPanel(new GridLayout(1, 5, 8, 0));
        toolbar.setBackground(new Color(250, 250, 250));
        toolbar.setPreferredSize(new Dimension(0, 36));

        analyzeButton = createStyledButton("▶ Analyze URL", e -> analyzeURLAction());
        simulationButton = createStyledButton("⚙ Safe Simulation", e -> runSafeSimulationAction());
        viewFeaturesButton = createStyledButton("📋 View Features", e -> viewFeaturesAction());
        viewLogButton = createStyledButton("📑 View Security Log", e -> viewSecurityLogAction());
        clearButton = createStyledButton("🗑 Clear Output", e -> clearOutputAction());

        toolbar.add(analyzeButton);
        toolbar.add(simulationButton);
        toolbar.add(viewFeaturesButton);
        toolbar.add(viewLogButton);
        toolbar.add(clearButton);

        return toolbar;
    }

    /**
     * Creates a custom-styled button with soft blue-silver gradient matching the reference image.
     */
    private JButton createStyledButton(String text, java.awt.event.ActionListener listener) {
        JButton button = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int w = getWidth();
                int h = getHeight();

                Color top;
                Color bot;

                if (getModel().isPressed()) {
                    top = new Color(205, 222, 242);
                    bot = new Color(180, 204, 232);
                } else if (getModel().isRollover()) {
                    top = new Color(236, 244, 254);
                    bot = new Color(208, 226, 248);
                } else {
                    top = new Color(245, 249, 255);
                    bot = new Color(222, 235, 250);
                }

                GradientPaint gp = new GradientPaint(0, 0, top, 0, h, bot);
                g2.setPaint(gp);
                g2.fillRoundRect(0, 0, w - 1, h - 1, 3, 3);

                g2.setColor(new Color(165, 185, 212));
                g2.drawRoundRect(0, 0, w - 1, h - 1, 3, 3);
                g2.dispose();

                super.paintComponent(g);
            }
        };

        button.setContentAreaFilled(false);
        button.setFocusPainted(false);
        button.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        button.setForeground(new Color(30, 40, 55));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        button.addActionListener(listener);
        return button;
    }

    private JPanel createTerminalOutputPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Color.WHITE);
        panel.setBorder(BorderFactory.createLineBorder(new Color(205, 212, 220), 1));

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font("Consolas", Font.PLAIN, 13));
        outputArea.setBackground(Color.WHITE);
        outputArea.setForeground(new Color(35, 40, 50));
        outputArea.setMargin(new Insets(12, 16, 12, 16));

        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setBorder(null);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private void printSystemReadyBanner() {
        outputArea.setText("");
        outputArea.append("======================================================================\n");
        outputArea.append("AI-BASED PHISHING URL DETECTION SYSTEM\n");
        outputArea.append("======================================================================\n");
        outputArea.append("[INFO] System initialized. Ready for URL inspection.\n");
        outputArea.append("[INFO] Machine Learning Engine : Weka 3.8.6 Random Forest (100 Trees)\n");
        outputArea.append("[INFO] Trained Benchmark Model : model/phishing_model.model\n");
        outputArea.append("[INFO] Evaluated Test Accuracy : 97.56% (2,211 Unseen Test Instances)\n");
        outputArea.append("[INFO] Defensive Guarantee    : No external web payloads or scripts executed.\n");
        outputArea.append("----------------------------------------------------------------------\n");
        outputArea.append("Enter a target URL above and click [▶ Analyze URL] or click [⚙ Safe Simulation].\n\n");
    }

    private void warmupModelInBackground() {
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                URLPredictionService.getPredictor();
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    systemStatusLabel.setText("● SYSTEM READY");
                    systemStatusLabel.setForeground(new Color(20, 130, 50));
                } catch (Exception e) {
                    systemStatusLabel.setText("● MODEL ERROR");
                    systemStatusLabel.setForeground(Color.RED);
                    outputArea.append("[ERROR] Model initialization failed: " + e.getMessage() + "\n");
                }
            }
        };
        worker.execute();
    }

    /**
     * Executes single URL analysis and displays structured output in the terminal.
     */
    private void analyzeURLAction() {
        String input = urlInputField.getText().trim();
        if (input.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please enter a website URL to inspect.",
                    "Empty Input",
                    JOptionPane.WARNING_MESSAGE);
            urlInputField.requestFocus();
            return;
        }

        systemStatusLabel.setText("● ANALYZING...");
        systemStatusLabel.setForeground(new Color(210, 110, 0));
        analyzeButton.setEnabled(false);

        SwingWorker<PredictionResult, Void> worker = new SwingWorker<PredictionResult, Void>() {
            @Override
            protected PredictionResult doInBackground() throws Exception {
                return URLPredictionService.analyzeURL(input);
            }

            @Override
            protected void done() {
                analyzeButton.setEnabled(true);
                systemStatusLabel.setText("● SYSTEM READY");
                systemStatusLabel.setForeground(new Color(20, 130, 50));

                try {
                    lastResult = get();
                    displayFormattedAnalysis(lastResult);
                } catch (Exception e) {
                    outputArea.append("\n[ERROR] Evaluation failed for URL: " + input + "\n");
                    outputArea.append("[REASON] " + e.getMessage() + "\n\n");
                }
            }
        };
        worker.execute();
    }

    /**
     * Formats and prints single URL analysis matching the reference security output style.
     */
    private void displayFormattedAnalysis(PredictionResult res) {
        StringBuilder sb = new StringBuilder();
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        sb.append("======================================================================\n");
        sb.append("SAFE URL SECURITY INSPECTION\n");
        sb.append("======================================================================\n");
        sb.append("[INFO] Inspection Mode : Safe Offline Lexical & ML Analysis\n");
        sb.append("[INFO] Execution Policy: No remote website code was executed.\n");
        sb.append("[TIMESTAMP] ").append(timestamp).append("\n\n");

        sb.append("[INSPECTION] Target URL: ").append(res.getUrl()).append("\n");
        sb.append("[ANALYSIS] Extracting 30 lexical and structural URL attributes...\n");

        // Key feature highlights
        int highlighted = 0;
        for (Map.Entry<String, String> entry : res.getFeatureDetails().entrySet()) {
            if (entry.getValue().contains("Malicious") || entry.getValue().contains("Suspicious") || highlighted < 4) {
                sb.append("  • ").append(String.format("%-26s: %s\n", entry.getKey(), entry.getValue()));
                highlighted++;
            }
        }
        sb.append("\n");

        if (res.isPhishing()) {
            sb.append("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            sb.append("                          SECURITY ALERT!                             \n");
            sb.append("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            sb.append("Possible Phishing / Malicious Website Detected!\n");
            sb.append(String.format("Target URL      : %s\n", res.getUrl()));
            sb.append(String.format("Prediction      : %s\n", res.getPredictedClass()));
            sb.append(String.format("Risk Level      : %s RISK\n", res.getRiskLevel()));
            sb.append(String.format("Confidence      : %s\n", res.getConfidencePercentage()));
            sb.append(String.format("Class Breakdown : [Phishing: %.2f%% | Legitimate: %.2f%%]\n",
                    res.getPhishingProbability() * 100.0, res.getLegitimateProbability() * 100.0));
            sb.append("Detection Type  : MACHINE LEARNING (RANDOM FOREST)\n");
            sb.append("Threat Notice   : Learned URL patterns strongly correlate with credential harvesting.\n");
            sb.append("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        } else {
            sb.append("----------------------------------------------------------------------\n");
            sb.append("                        SECURITY ASSESSMENT                           \n");
            sb.append("----------------------------------------------------------------------\n");
            sb.append("Website Appears Consistent with Legitimate Profiles.\n");
            sb.append(String.format("Target URL      : %s\n", res.getUrl()));
            sb.append(String.format("Prediction      : %s\n", res.getPredictedClass()));
            sb.append(String.format("Risk Level      : %s RISK\n", res.getRiskLevel()));
            sb.append(String.format("Confidence      : %s\n", res.getConfidencePercentage()));
            sb.append(String.format("Class Breakdown : [Legitimate: %.2f%% | Phishing: %.2f%%]\n",
                    res.getLegitimateProbability() * 100.0, res.getPhishingProbability() * 100.0));
            sb.append("Detection Type  : MACHINE LEARNING (RANDOM FOREST)\n");
            sb.append("----------------------------------------------------------------------\n");
        }

        sb.append("[LOG] Assessment logged to results/test_results.txt\n\n");
        sb.append("[INSPECTION COMPLETED]\n");
        sb.append("[INFO] Analysis completed successfully without host vulnerability risk.\n\n");

        outputArea.setText(sb.toString());
        outputArea.setCaretPosition(0);
    }

    /**
     * Executes the Safe Simulation mode matching the reference screenshot.
     */
    private void runSafeSimulationAction() {
        systemStatusLabel.setText("● SIMULATION RUNNING...");
        systemStatusLabel.setForeground(new Color(210, 110, 0));
        simulationButton.setEnabled(false);

        SwingWorker<Void, String> worker = new SwingWorker<Void, String>() {
            @Override
            protected Void doInBackground() throws Exception {
                publish("======================================================================\n");
                publish("SAFE PHISHING DETECTION SIMULATION\n");
                publish("======================================================================\n");
                publish("[INFO] Simulation mode only.\n");
                publish("[INFO] No external computer is scanned / no website code executed.\n\n");

                Thread.sleep(300);

                String[] simulationUrls = {
                        "https://www.google.com",
                        "http://192.168.1.1/paypal-login.html",
                        "https://secure-login-verify-account.bankofamerica.com.evil-phishing.org/login",
                        "http://https-paypal-login-alert.net/myaccount"
                };

                for (int i = 0; i < simulationUrls.length; i++) {
                    String simUrl = simulationUrls[i];
                    publish(String.format("[SIMULATION %d/4] Evaluating: %s\n", i + 1, simUrl));
                    PredictionResult res = URLPredictionService.analyzeURL(simUrl);
                    lastResult = res;

                    if (res.isPhishing()) {
                        publish("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                        publish("                          SECURITY ALERT!                             \n");
                        publish("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                        publish("Possible Phishing Attempt Detected!\n");
                        publish(String.format("Target URL      : %s\n", res.getUrl()));
                        publish(String.format("Prediction      : %s\n", res.getPredictedClass()));
                        publish(String.format("Risk Level      : %s RISK\n", res.getRiskLevel()));
                        publish(String.format("Confidence      : %s\n", res.getConfidencePercentage()));
                        publish(String.format("Class Breakdown : [Phishing: %.2f%% | Legitimate: %.2f%%]\n",
                                res.getPhishingProbability() * 100.0, res.getLegitimateProbability() * 100.0));
                        publish("Detection Type  : SAFE SIMULATION (RANDOM FOREST)\n");
                        publish("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                        publish("[LOG] Alert logged to results/test_results.txt\n\n");
                    } else {
                        publish("----------------------------------------------------------------------\n");
                        publish("                        SECURITY ASSESSMENT                           \n");
                        publish("----------------------------------------------------------------------\n");
                        publish("Legitimate URL Verified.\n");
                        publish(String.format("Target URL      : %s\n", res.getUrl()));
                        publish(String.format("Prediction      : %s\n", res.getPredictedClass()));
                        publish(String.format("Risk Level      : %s RISK\n", res.getRiskLevel()));
                        publish(String.format("Confidence      : %s\n", res.getConfidencePercentage()));
                        publish("Detection Type  : SAFE SIMULATION\n");
                        publish("----------------------------------------------------------------------\n\n");
                    }

                    Thread.sleep(400);
                }

                publish("[SIMULATION COMPLETED]\n");
                publish("[INFO] All 4 simulation vectors evaluated successfully.\n");
                publish("[INFO] No real network intrusion or web exploitation was performed.\n\n");
                return null;
            }

            @Override
            protected void process(java.util.List<String> chunks) {
                for (String chunk : chunks) {
                    outputArea.append(chunk);
                }
                outputArea.setCaretPosition(outputArea.getDocument().getLength());
            }

            @Override
            protected void done() {
                simulationButton.setEnabled(true);
                systemStatusLabel.setText("● SYSTEM READY");
                systemStatusLabel.setForeground(new Color(20, 130, 50));
            }
        };

        outputArea.setText("");
        worker.execute();
    }

    /**
     * Prints the complete 30-feature breakdown into the terminal and opens the table dialog.
     */
    private void viewFeaturesAction() {
        if (lastResult == null) {
            String currentUrl = urlInputField.getText().trim();
            if (!currentUrl.isEmpty()) {
                analyzeURLAction();
                return;
            }
            JOptionPane.showMessageDialog(this,
                    "Please analyze a URL first to inspect its extracted features.",
                    "No Features Available",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("======================================================================\n");
        sb.append("EXTRACTED FEATURE BREAKDOWN (30 ARFF ATTRIBUTES)\n");
        sb.append("======================================================================\n");
        sb.append("Inspected URL: ").append(lastResult.getUrl()).append("\n");
        sb.append("Prediction   : ").append(lastResult.getPredictedClass()).append(" (Confidence: ").append(lastResult.getConfidencePercentage()).append(")\n");
        sb.append("----------------------------------------------------------------------\n");

        int idx = 1;
        for (Map.Entry<String, String> entry : lastResult.getFeatureDetails().entrySet()) {
            sb.append(String.format("%2d. %-28s : %s\n", idx++, entry.getKey(), entry.getValue()));
        }
        sb.append("======================================================================\n\n");

        outputArea.setText(sb.toString());
        outputArea.setCaretPosition(0);
    }

    /**
     * Reads and displays the permanent test log results directly into the terminal area.
     */
    private void viewSecurityLogAction() {
        File logFile = new File("results/test_results.txt");
        if (!logFile.exists()) {
            outputArea.setText("[INFO] Security log file not found at results/test_results.txt.\nRun SystemTestSuite to generate the complete log.\n");
            return;
        }
        try {
            String content = Files.readString(logFile.toPath());
            outputArea.setText(content);
            outputArea.setCaretPosition(0);
        } catch (Exception e) {
            outputArea.setText("[ERROR] Could not read security log: " + e.getMessage() + "\n");
        }
    }

    private void clearOutputAction() {
        printSystemReadyBanner();
        systemStatusLabel.setText("● SYSTEM READY");
        systemStatusLabel.setForeground(new Color(20, 130, 50));
        urlInputField.setText("https://www.google.com");
        urlInputField.requestFocus();
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }

        SwingUtilities.invokeLater(() -> {
            MainGUI gui = new MainGUI();
            gui.setVisible(true);
        });
    }
}
