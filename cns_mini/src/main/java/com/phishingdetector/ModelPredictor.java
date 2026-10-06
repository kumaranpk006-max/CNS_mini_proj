package com.phishingdetector;

import weka.classifiers.Classifier;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SerializationHelper;
import weka.core.converters.ArffLoader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Map;

/**
 * ModelPredictor
 * Loads the trained Random Forest model and provides robust prediction services.
 * Enforces strict feature validation and attribute structure consistency.
 */
public class ModelPredictor {

    public static final String DEFAULT_MODEL_PATH = "model/phishing_model.model";
    public static final String DEFAULT_HEADER_PATH = "model/model_header.arff";

    private Classifier classifier;
    private Instances header;

    /**
     * Default constructor: Loads model and header from default locations.
     */
    public ModelPredictor() throws Exception {
        this(DEFAULT_MODEL_PATH, DEFAULT_HEADER_PATH);
    }

    /**
     * Constructor loading from custom paths.
     */
    public ModelPredictor(String modelPath, String headerPath) throws Exception {
        loadModel(modelPath, headerPath);
    }

    /**
     * Loads and verifies the model file and header structure.
     */
    public synchronized void loadModel(String modelPath, String headerPath) throws Exception {
        File modelFile = new File(modelPath);
        if (!modelFile.exists()) {
            throw new FileNotFoundException("Trained model file not found at: " + modelFile.getAbsolutePath()
                    + "\nPlease train the model first by running ModelTrainer.");
        }

        System.out.println("[ModelPredictor] Loading trained model from: " + modelFile.getPath());
        this.classifier = (Classifier) SerializationHelper.read(modelFile.getAbsolutePath());

        // Load header structure
        File headerFile = new File(headerPath);
        if (headerFile.exists()) {
            System.out.println("[ModelPredictor] Loading model header from: " + headerFile.getPath());
            ArffLoader loader = new ArffLoader();
            loader.setFile(headerFile);
            this.header = loader.getStructure();
        } else {
            System.out.println("[ModelPredictor] Header file not found at " + headerPath + ", falling back to DatasetLoader...");
            Instances fullData = DatasetLoader.loadDataset();
            this.header = new Instances(fullData, 0);
        }

        if (this.header.classIndex() < 0) {
            Attribute classAttr = this.header.attribute(DatasetLoader.CLASS_ATTRIBUTE_NAME);
            if (classAttr != null) {
                this.header.setClassIndex(classAttr.index());
            } else {
                this.header.setClassIndex(this.header.numAttributes() - 1);
            }
        }

        // Verify header consistency
        if (this.header.numAttributes() != DatasetLoader.EXPECTED_NUM_ATTRIBUTES) {
            throw new IllegalStateException("Model header attribute count mismatch: Expected "
                    + DatasetLoader.EXPECTED_NUM_ATTRIBUTES + ", found " + this.header.numAttributes());
        }

        System.out.println("[ModelPredictor] Model and header successfully loaded and validated.");
        System.out.println("  - Algorithm      : " + classifier.getClass().getSimpleName());
        System.out.println("  - Attribute Count: " + header.numAttributes());
        System.out.println("  - Class Attribute: " + header.classAttribute().name() + " (Values: " + header.classAttribute().numValues() + ")");
    }

    /**
     * Checks if the classifier is loaded.
     */
    public boolean isLoaded() {
        return classifier != null && header != null;
    }

    /**
     * Converts an array of 30 discrete feature integers into a valid Weka Instance.
     * Enforces strict nominal value validation.
     *
     * @param featureValues Array of exactly 30 integers corresponding to input features.
     * @return Weka Instance attached to the header template.
     */
    public Instance createInstance(int[] featureValues) {
        if (!isLoaded()) {
            throw new IllegalStateException("ModelPredictor is not loaded! Call loadModel() first.");
        }
        if (featureValues == null || featureValues.length != 30) {
            int length = (featureValues == null) ? 0 : featureValues.length;
            throw new IllegalArgumentException("Feature count mismatch! Expected 30 input features, but received: " + length);
        }

        Instance inst = new DenseInstance(header.numAttributes());
        inst.setDataset(header);

        for (int i = 0; i < 30; i++) {
            Attribute attr = header.attribute(i);
            String valStr = String.valueOf(featureValues[i]);

            // Validate that value exists in the nominal attribute's allowed values
            int valIndex = attr.indexOfValue(valStr);
            if (valIndex == -1) {
                throw new IllegalArgumentException(String.format(
                        "Invalid value '%s' for attribute '%s' (Index %d)! Allowed values are: %s",
                        valStr, attr.name(), i, getAttributeAllowedValuesString(attr)));
            }
            inst.setValue(attr, valStr);
        }

        // Target class is missing for prediction
        inst.setClassMissing();
        return inst;
    }

    /**
     * Predicts whether a URL is Legitimate or Phishing given its 30 extracted features.
     *
     * @param featureValues Array of 30 integer feature values.
     * @param url The input URL string.
     * @param featureDetails Optional map of feature names to descriptions.
     * @return PredictionResult containing class, probabilities, confidence, and risk level.
     * @throws Exception If prediction fails.
     */
    public PredictionResult predict(int[] featureValues, String url, Map<String, String> featureDetails) throws Exception {
        Instance inst = createInstance(featureValues);
        return predict(inst, url, featureDetails);
    }

    /**
     * Predicts directly from a Weka Instance.
     */
    public PredictionResult predict(Instance instance, String url, Map<String, String> featureDetails) throws Exception {
        if (!isLoaded()) {
            throw new IllegalStateException("ModelPredictor is not loaded! Call loadModel() first.");
        }

        // Get class probability distribution
        double[] distribution = classifier.distributionForInstance(instance);

        Attribute classAttr = header.classAttribute();
        int phishIndex = classAttr.indexOfValue("-1");
        int legitIndex = classAttr.indexOfValue("1");

        double phishProb = (phishIndex >= 0 && phishIndex < distribution.length) ? distribution[phishIndex] : 0.0;
        double legitProb = (legitIndex >= 0 && legitIndex < distribution.length) ? distribution[legitIndex] : 0.0;

        String predictedClass;
        String rawClassValue;
        double confidence;

        if (legitProb >= phishProb) {
            predictedClass = Utils.CLASS_LEGITIMATE;
            rawClassValue = "1";
            confidence = legitProb;
        } else {
            predictedClass = Utils.CLASS_PHISHING;
            rawClassValue = "-1";
            confidence = phishProb;
        }

        String riskLevel = Utils.calculateRiskLevel(predictedClass, confidence);

        return new PredictionResult(
                url,
                predictedClass,
                rawClassValue,
                confidence,
                riskLevel,
                legitProb,
                phishProb,
                featureDetails
        );
    }

    private String getAttributeAllowedValuesString(Attribute attr) {
        StringBuilder sb = new StringBuilder("{ ");
        for (int i = 0; i < attr.numValues(); i++) {
            sb.append(attr.value(i));
            if (i < attr.numValues() - 1) sb.append(", ");
        }
        sb.append(" }");
        return sb.toString();
    }

    public Instances getHeader() {
        return header;
    }

    public Classifier getClassifier() {
        return classifier;
    }

    /**
     * Standalone main method to test model loading and predictions.
     */
    public static void main(String[] args) {
        System.out.println("Testing ModelPredictor independently...\n");
        try {
            ModelPredictor predictor = new ModelPredictor();

            // Test Case 1: Synthetic Legitimate Profile (All Safe Indicators)
            // Redirect = 0, others = 1
            int[] legitFeatures = new int[30];
            for (int i = 0; i < 30; i++) {
                legitFeatures[i] = (i == 18) ? 0 : 1; // Attribute 18 (Redirect) uses {0, 1}
            }

            PredictionResult res1 = predictor.predict(legitFeatures, "https://www.google.com", null);
            System.out.println("Test Case 1 (Synthetic Safe Vector):");
            System.out.println("  " + res1);
            System.out.println("  Predicted Class: " + res1.getPredictedClass());
            System.out.println("  Confidence     : " + res1.getConfidencePercentage());
            System.out.println("  Risk Level     : " + res1.getRiskLevel());

            // Test Case 2: Synthetic Phishing Profile (All Malicious Indicators)
            // Redirect = 1, others = -1
            int[] phishFeatures = new int[30];
            for (int i = 0; i < 30; i++) {
                phishFeatures[i] = (i == 18) ? 1 : -1; // Attribute 18 (Redirect) uses {0, 1}
            }

            PredictionResult res2 = predictor.predict(phishFeatures, "http://192.168.1.1/paypal-login/verify@security", null);
            System.out.println("\nTest Case 2 (Synthetic Malicious Vector):");
            System.out.println("  " + res2);
            System.out.println("  Predicted Class: " + res2.getPredictedClass());
            System.out.println("  Confidence     : " + res2.getConfidencePercentage());
            System.out.println("  Risk Level     : " + res2.getRiskLevel());

            // Test Case 3: Error Handling Test (Feature count mismatch)
            System.out.println("\nTest Case 3: Testing feature mismatch error handling...");
            try {
                int[] invalidFeatures = new int[15]; // Wrong length
                predictor.predict(invalidFeatures, "http://example.com", null);
                System.err.println("FAILED: Feature mismatch was not caught!");
            } catch (IllegalArgumentException e) {
                System.out.println("SUCCESS: Correctly caught invalid feature count: " + e.getMessage());
            }

            System.out.println("\nModelPredictor test PASSED successfully!");
        } catch (Exception e) {
            System.err.println("ModelPredictor test FAILED: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
