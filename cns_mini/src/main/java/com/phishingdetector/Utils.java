package com.phishingdetector;

import java.net.URI;
import java.net.URL;

/**
 * Utils
 * Utility helper methods for URL validation, class label translation,
 * risk level calculation, and percentage formatting.
 */
public class Utils {

    public static final String CLASS_LEGITIMATE = "LEGITIMATE";
    public static final String CLASS_PHISHING = "PHISHING";

    public static final String RISK_LOW = "LOW";
    public static final String RISK_MEDIUM = "MEDIUM";
    public static final String RISK_HIGH = "HIGH";

    /**
     * Maps raw nominal class values ("-1", "1") to human-readable strings.
     *
     * @param rawValue Nominal value string from Weka model.
     * @return "LEGITIMATE" or "PHISHING".
     */
    public static String mapClassValue(String rawValue) {
        if ("1".equals(rawValue)) {
            return CLASS_LEGITIMATE;
        } else if ("-1".equals(rawValue)) {
            return CLASS_PHISHING;
        }
        return "UNKNOWN (" + rawValue + ")";
    }

    /**
     * Determines the risk level based on predicted class and prediction confidence probability.
     *
     * Rules:
     * - LEGITIMATE with high confidence (>= 75%) -> LOW Risk
     * - LEGITIMATE with lower confidence (< 75%)  -> MEDIUM Risk (borderline characteristics)
     * - PHISHING with lower confidence (< 75%)    -> MEDIUM Risk
     * - PHISHING with high confidence (>= 75%)   -> HIGH Risk
     *
     * @param prediction Predicted class ("LEGITIMATE" or "PHISHING").
     * @param confidence Probability score in range [0.0, 1.0].
     * @return "LOW", "MEDIUM", or "HIGH".
     */
    public static String calculateRiskLevel(String prediction, double confidence) {
        if (CLASS_LEGITIMATE.equalsIgnoreCase(prediction)) {
            if (confidence >= 0.75) {
                return RISK_LOW;
            } else {
                return RISK_MEDIUM;
            }
        } else if (CLASS_PHISHING.equalsIgnoreCase(prediction)) {
            if (confidence >= 0.75) {
                return RISK_HIGH;
            } else {
                return RISK_MEDIUM;
            }
        }
        return RISK_MEDIUM;
    }

    /**
     * Validates whether a given string is a syntactically valid URL.
     * Ensures scheme is http or https and host is present.
     *
     * @param urlString Input URL string.
     * @return true if valid, false otherwise.
     */
    public static boolean isValidURL(String urlString) {
        if (urlString == null || urlString.trim().isEmpty()) {
            return false;
        }
        String trimmed = urlString.trim();
        // Prepend http if user omitted protocol for forgiving input
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            trimmed = "http://" + trimmed;
        }
        try {
            URI uri = new URI(trimmed);
            URL url = uri.toURL();
            String host = url.getHost();
            return host != null && !host.trim().isEmpty() && host.contains(".");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Normalizes a URL string by ensuring a scheme is present and trimming whitespace.
     */
    public static String normalizeURL(String rawUrl) {
        if (rawUrl == null) return "";
        String trimmed = rawUrl.trim();
        if (!trimmed.toLowerCase().startsWith("http://") && !trimmed.toLowerCase().startsWith("https://")) {
            return "http://" + trimmed;
        }
        return trimmed;
    }

    /**
     * Formats a probability value (e.g. 0.9532) as a percentage string (e.g. "95.32%").
     */
    public static String formatPercentage(double probability) {
        return String.format("%.2f%%", probability * 100.0);
    }
}
