package com.phishingdetector;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * PredictionResult
 * Immutable value object holding the output of an ML prediction for a URL.
 */
public class PredictionResult {

    private final String url;
    private final String predictedClass;     // "LEGITIMATE" or "PHISHING"
    private final String rawClassValue;       // "1" or "-1"
    private final double confidence;          // 0.0 to 1.0 (e.g. 0.952)
    private final String riskLevel;           // "LOW", "MEDIUM", or "HIGH"
    private final double legitimateProbability;
    private final double phishingProbability;
    private final Map<String, String> featureDetails; // Feature name -> Extracted value / label

    public PredictionResult(String url,
                            String predictedClass,
                            String rawClassValue,
                            double confidence,
                            String riskLevel,
                            double legitimateProbability,
                            double phishingProbability,
                            Map<String, String> featureDetails) {
        this.url = url;
        this.predictedClass = predictedClass;
        this.rawClassValue = rawClassValue;
        this.confidence = confidence;
        this.riskLevel = riskLevel;
        this.legitimateProbability = legitimateProbability;
        this.phishingProbability = phishingProbability;
        this.featureDetails = featureDetails != null 
                ? Collections.unmodifiableMap(new LinkedHashMap<>(featureDetails))
                : Collections.emptyMap();
    }

    public String getUrl() {
        return url;
    }

    public String getPredictedClass() {
        return predictedClass;
    }

    public String getRawClassValue() {
        return rawClassValue;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getConfidencePercentage() {
        return Utils.formatPercentage(confidence);
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public double getLegitimateProbability() {
        return legitimateProbability;
    }

    public double getPhishingProbability() {
        return phishingProbability;
    }

    public Map<String, String> getFeatureDetails() {
        return featureDetails;
    }

    public boolean isLegitimate() {
        return Utils.CLASS_LEGITIMATE.equalsIgnoreCase(predictedClass);
    }

    public boolean isPhishing() {
        return Utils.CLASS_PHISHING.equalsIgnoreCase(predictedClass);
    }

    @Override
    public String toString() {
        return String.format("PredictionResult [URL=%s, Prediction=%s (Risk: %s, Confidence: %.2f%%, P(Legit)=%.2f%%, P(Phish)=%.2f%%)]",
                url, predictedClass, riskLevel, confidence * 100.0,
                legitimateProbability * 100.0, phishingProbability * 100.0);
    }
}
