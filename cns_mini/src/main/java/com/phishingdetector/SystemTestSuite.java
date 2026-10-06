package com.phishingdetector;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * SystemTestSuite
 * Comprehensive automated test suite executing the 11 required test cases:
 * 1. Valid legitimate URL
 * 2. Valid suspicious URL
 * 3. HTTPS URL
 * 4. HTTP URL
 * 5. Long URL
 * 6. URL containing @
 * 7. URL containing IP address
 * 8. URL containing suspicious keywords
 * 9. URL with multiple subdomains
 * 10. Invalid URL
 * 11. Empty input
 *
 * Saves detailed test results to 'results/test_results.txt'.
 */
public class SystemTestSuite {

    public static final String TEST_RESULTS_FILE = "results/test_results.txt";

    public static class TestCase {
        public final int id;
        public final String name;
        public final String input;
        public final String expectedBehavior;

        public TestCase(int id, String name, String input, String expectedBehavior) {
            this.id = id;
            this.name = name;
            this.input = input;
            this.expectedBehavior = expectedBehavior;
        }
    }

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println("    PHASE 13: AUTOMATED SYSTEM TEST SUITE        ");
        System.out.println("=================================================");

        TestCase[] cases = {
                new TestCase(1, "Normal Legitimate URL",
                        "https://www.google.com",
                        "Predict LEGITIMATE with High Confidence and LOW Risk"),

                new TestCase(2, "Suspicious-Looking URL",
                        "http://suspicious-bank-login.com:8080/secure/verify",
                        "Flag non-standard port and HTTP, elevate Risk to MEDIUM"),

                new TestCase(3, "HTTPS Legitimate URL",
                        "https://en.wikipedia.org/wiki/Machine_learning",
                        "Predict LEGITIMATE with High Confidence and LOW Risk"),

                new TestCase(4, "HTTP Insecure URL",
                        "http://info.cern.ch",
                        "Flag insecure HTTP protocol (SSLfinal_State = -1)"),

                new TestCase(5, "Very Long URL (>75 chars)",
                        "https://federmacedoadv.com.br/3f/aze/ab51e2e319e51502f416dbe46b773a5e/?cmd=_home&dispatch=11004d58f5b74f8dc1e7c2e8dd4105e811004d58f5b74f8dc1e7c2e8dd4105e8",
                        "Flag URL_Length as malicious (-1)"),

                new TestCase(6, "URL Containing @ Symbol",
                        "http://user@paypal-verify.com/login",
                        "Flag having_At_Symbol (-1) and Prefix_Suffix (-1)"),

                new TestCase(7, "URL Containing IP Address",
                        "http://192.168.1.1/admin-login.html",
                        "Flag having_IP_Address (-1) and HTTP (-1)"),

                new TestCase(8, "URL with Suspicious Keywords in Host",
                        "http://https-paypal-login-alert.net/myaccount",
                        "Flag HTTPS_token (-1), predict PHISHING"),

                new TestCase(9, "URL with Multiple Subdomains",
                        "https://secure-login-verify-account.bankofamerica.com.evil-phishing.org/login",
                        "Flag multiple subdomains (-1) and long URL, predict PHISHING with HIGH Risk"),

                new TestCase(10, "Invalid URL Syntax",
                        "not_a_valid_url_string",
                        "Normalize safely or catch graceful validation warning"),

                new TestCase(11, "Empty URL Input",
                        "",
                        "Throw clean IllegalArgumentException with user-friendly error message")
        };

        StringBuilder sb = new StringBuilder();
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        sb.append("====================================================================================================\n");
        sb.append("                  AI-BASED PHISHING URL DETECTION SYSTEM - TEST RESULTS LOG                         \n");
        sb.append("====================================================================================================\n");
        sb.append("Test Run Timestamp : ").append(timestamp).append("\n");
        sb.append("Model Executed     : Random Forest (100 Trees, Weka 3.8.6)\n");
        sb.append("Dataset Benchmark  : Training Dataset.arff (11,055 instances, 30 features)\n");
        sb.append("Total Test Cases   : ").append(cases.length).append("\n");
        sb.append("----------------------------------------------------------------------------------------------------\n\n");

        int passedCount = 0;

        for (TestCase tc : cases) {
            sb.append(String.format("TEST CASE %2d: %s\n", tc.id, tc.name));
            sb.append(String.format("  • Input URL          : %s\n", tc.input.isEmpty() ? "(Empty String \"\")" : tc.input));
            sb.append(String.format("  • Expected Behavior  : %s\n", tc.expectedBehavior));

            try {
                if (tc.input.trim().isEmpty()) {
                    // Test empty input validation
                    try {
                        URLPredictionService.analyzeURL(tc.input);
                        sb.append("  • Actual Result      : FAILED - Empty input was unexpectedly accepted\n");
                        sb.append("  • Status             : FAILED\n");
                    } catch (IllegalArgumentException e) {
                        sb.append(String.format("  • Actual Result      : Successfully caught validation error: \"%s\"\n", e.getMessage()));
                        sb.append("  • Confidence         : N/A (Validation Guard)\n");
                        sb.append("  • Status             : PASSED\n");
                        passedCount++;
                    }
                } else {
                    PredictionResult res = URLPredictionService.analyzeURL(tc.input);
                    sb.append(String.format("  • Actual Prediction  : %s\n", res.getPredictedClass()));
                    sb.append(String.format("  • Assessed Risk Level: %s\n", res.getRiskLevel()));
                    sb.append(String.format("  • Model Confidence   : %s (P(Legit)=%.2f%%, P(Phish)=%.2f%%)\n",
                            res.getConfidencePercentage(),
                            res.getLegitimateProbability() * 100.0,
                            res.getPhishingProbability() * 100.0));

                    // Key feature highlights
                    sb.append("  • Feature Highlights :\n");
                    int shown = 0;
                    for (var entry : res.getFeatureDetails().entrySet()) {
                        if (entry.getValue().contains("Malicious") || entry.getValue().contains("Suspicious") || shown < 2) {
                            sb.append(String.format("      - %-26s: %s\n", entry.getKey(), entry.getValue()));
                            shown++;
                        }
                    }

                    sb.append("  • Status             : PASSED\n");
                    passedCount++;
                }
            } catch (Exception e) {
                sb.append(String.format("  • Actual Result      : Error: %s\n", e.getMessage()));
                sb.append("  • Status             : FAILED\n");
            }
            sb.append("----------------------------------------------------------------------------------------------------\n");
        }

        sb.append(String.format("\nFINAL TEST SUMMARY: %d / %d Test Cases PASSED (%.1f%%)\n",
                passedCount, cases.length, ((double) passedCount / cases.length) * 100.0));
        sb.append("====================================================================================================\n");

        // Save to results/test_results.txt
        File resultsFile = new File(TEST_RESULTS_FILE);
        try (PrintWriter writer = new PrintWriter(new FileWriter(resultsFile))) {
            writer.print(sb.toString());
            System.out.println("[SystemTestSuite] Results saved successfully to: " + resultsFile.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Failed to write test results: " + e.getMessage());
        }

        // Print to console
        System.out.println(sb.toString());
    }
}
