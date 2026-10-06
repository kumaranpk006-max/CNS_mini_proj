package com.phishingdetector;

/**
 * URLPredictionService
 * Coordinates the end-to-end prediction pipeline:
 * Input URL -> Validation -> Feature Extraction -> Weka Instance -> Random Forest -> PredictionResult
 *
 * Keeps a singleton / cached instance of ModelPredictor in memory so the model
 * is NOT reloaded from disk on every prediction request.
 */
public class URLPredictionService {

    private static ModelPredictor predictorInstance;

    /**
     * Obtains the shared ModelPredictor instance (lazy-loaded singleton).
     */
    public static synchronized ModelPredictor getPredictor() throws Exception {
        if (predictorInstance == null || !predictorInstance.isLoaded()) {
            System.out.println("[URLPredictionService] Initializing shared ModelPredictor instance...");
            predictorInstance = new ModelPredictor();
        }
        return predictorInstance;
    }

    /**
     * Executes the complete end-to-end analysis and prediction pipeline for a given URL.
     *
     * @param rawUrl The URL input string.
     * @return PredictionResult containing class, risk level, confidence, and feature breakdown.
     * @throws IllegalArgumentException If URL is null or blank.
     * @throws Exception If model inference or extraction fails.
     */
    public static PredictionResult analyzeURL(String rawUrl) throws Exception {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("URL input cannot be empty. Please enter a valid website URL.");
        }

        String inputUrl = rawUrl.trim();

        // 1. Basic URL validation check
        if (!Utils.isValidURL(inputUrl)) {
            System.out.println("[URLPredictionService] Warning: Input URL has non-standard syntax: " + inputUrl);
        }

        // 2. Extract 30 features matching the ARFF schema
        URLFeatureExtractor.ExtractedFeatures extracted = URLFeatureExtractor.extractFeatures(inputUrl);

        // 3. Obtain shared ModelPredictor
        ModelPredictor predictor = getPredictor();

        // 4. Perform ML classification and risk assessment
        PredictionResult result = predictor.predict(
                extracted.getFeatureVector(),
                extracted.getNormalizedUrl(),
                extracted.getFeatureDetails()
        );

        return result;
    }

    /**
     * Standalone main method to test the end-to-end prediction pipeline on diverse test cases.
     */
    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println("      PHASE 10: END-TO-END URL PREDICTION        ");
        System.out.println("=================================================");

        String[] testCases = {
                "https://www.google.com",
                "https://en.wikipedia.org/wiki/Phishing",
                "https://github.com/torvalds/linux",
                "https://www.paypal.com/signin",
                "http://192.168.1.1/login.html",
                "http://bit.ly/secure-account-verification",
                "https://secure-login-verify-account.bankofamerica.com.evil-phishing.org/login",
                "http://user@paypal-verify.com/login",
                "http://https-paypal-login-alert.net/myaccount",
                "http://suspicious-bank-login.com:8080/secure/verify"
        };

        try {
            // Warm up predictor
            getPredictor();

            System.out.println("\nRunning predictions across benchmark test cases:\n");
            for (int i = 0; i < testCases.length; i++) {
                String testUrl = testCases[i];
                long start = System.nanoTime();
                PredictionResult res = analyzeURL(testUrl);
                long elapsedMs = (System.nanoTime() - start) / 1_000_000;

                System.out.printf("Test Case %2d:\n", i + 1);
                System.out.printf("  URL         : %s\n", res.getUrl());
                System.out.printf("  Prediction  : %s\n", res.getPredictedClass());
                System.out.printf("  Risk Level  : %s\n", res.getRiskLevel());
                System.out.printf("  Confidence  : %s (P(Legit)=%.2f%%, P(Phish)=%.2f%%)\n",
                        res.getConfidencePercentage(),
                        res.getLegitimateProbability() * 100.0,
                        res.getPhishingProbability() * 100.0);
                System.out.printf("  Latency     : %d ms\n", elapsedMs);
                System.out.println("-------------------------------------------------");
            }

            System.out.println("\nAll prediction tests completed successfully!");
            System.out.println("=================================================");

        } catch (Exception e) {
            System.err.println("URLPredictionService test FAILED: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
