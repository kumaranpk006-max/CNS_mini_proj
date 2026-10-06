package com.phishingdetector;

import weka.core.Attribute;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ArffLoader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * DatasetLoader
 * Responsible for loading, verifying, and validating the ARFF dataset.
 * Ensures strict schema and attribute consistency required for Weka ML models.
 */
public class DatasetLoader {

    public static final String DEFAULT_DATASET_PATH = "dataset/Training Dataset.arff";
    public static final String CLASS_ATTRIBUTE_NAME = "Result";
    public static final int EXPECTED_NUM_ATTRIBUTES = 31;
    public static final int EXPECTED_NUM_INSTANCES = 11055;

    // Canonical attribute names as declared in Training Dataset.arff
    public static final String[] ATTRIBUTE_NAMES = {
            "having_IP_Address",
            "URL_Length",
            "Shortining_Service",
            "having_At_Symbol",
            "double_slash_redirecting",
            "Prefix_Suffix",
            "having_Sub_Domain",
            "SSLfinal_State",
            "Domain_registeration_length",
            "Favicon",
            "port",
            "HTTPS_token",
            "Request_URL",
            "URL_of_Anchor",
            "Links_in_tags",
            "SFH",
            "Submitting_to_email",
            "Abnormal_URL",
            "Redirect",
            "on_mouseover",
            "RightClick",
            "popUpWidnow",
            "Iframe",
            "age_of_domain",
            "DNSRecord",
            "web_traffic",
            "Page_Rank",
            "Google_Index",
            "Links_pointing_to_page",
            "Statistical_report",
            "Result"
    };

    /**
     * Loads the dataset from the default file path.
     *
     * @return Weka Instances ready for training.
     * @throws Exception If loading or validation fails.
     */
    public static Instances loadDataset() throws Exception {
        return loadDataset(DEFAULT_DATASET_PATH);
    }

    /**
     * Loads and validates the ARFF dataset from a specified file path.
     *
     * @param filePath Path to the ARFF file.
     * @return Weka Instances with class index set.
     * @throws Exception If file is missing, format is invalid, or schema fails validation.
     */
    public static Instances loadDataset(String filePath) throws Exception {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException("Dataset file not found at: " + file.getAbsolutePath());
        }
        if (!file.canRead()) {
            throw new IOException("Cannot read dataset file at: " + file.getAbsolutePath());
        }

        System.out.println("[DatasetLoader] Loading dataset from: " + file.getPath());
        ArffLoader loader = new ArffLoader();
        loader.setFile(file);
        Instances data = loader.getDataSet();

        if (data == null) {
            throw new IOException("Failed to parse ARFF data: loader returned null.");
        }

        // Validate attribute count
        if (data.numAttributes() != EXPECTED_NUM_ATTRIBUTES) {
            throw new IllegalStateException("Attribute count mismatch! Expected " 
                    + EXPECTED_NUM_ATTRIBUTES + " attributes, but found: " + data.numAttributes());
        }

        // Validate attribute names and order
        for (int i = 0; i < EXPECTED_NUM_ATTRIBUTES; i++) {
            String actualName = data.attribute(i).name();
            String expectedName = ATTRIBUTE_NAMES[i];
            if (!actualName.equals(expectedName)) {
                throw new IllegalStateException("Attribute mismatch at index " + i 
                        + "! Expected '" + expectedName + "', found '" + actualName + "'");
            }
        }

        // Set class attribute (target)
        Attribute classAttr = data.attribute(CLASS_ATTRIBUTE_NAME);
        if (classAttr == null) {
            throw new IllegalStateException("Class attribute '" + CLASS_ATTRIBUTE_NAME + "' not found in dataset.");
        }
        data.setClassIndex(classAttr.index());

        // Validate class values
        if (!classAttr.isNominal() || classAttr.numValues() != 2) {
            throw new IllegalStateException("Class attribute must be binary nominal, but found: " + classAttr);
        }

        System.out.println("[DatasetLoader] Successfully loaded " + data.numInstances() + " instances with " 
                + data.numAttributes() + " attributes. Class index set to: " + data.classIndex() 
                + " (" + data.classAttribute().name() + ")");

        return data;
    }

    /**
     * Inspects and checks missing values in the dataset.
     *
     * @param data The Weka Instances to inspect.
     * @return Total count of missing values across all cells.
     */
    public static int checkMissingValues(Instances data) {
        int missingCount = 0;
        for (int i = 0; i < data.numInstances(); i++) {
            Instance inst = data.instance(i);
            for (int a = 0; a < data.numAttributes(); a++) {
                if (inst.isMissing(a)) {
                    missingCount++;
                }
            }
        }
        return missingCount;
    }

    /**
     * Generates and prints a comprehensive validation summary report.
     *
     * @param data Loaded Weka Instances.
     */
    public static void printDatasetSummary(Instances data) {
        System.out.println("\n=================================================");
        System.out.println("              DATASET SUMMARY REPORT             ");
        System.out.println("=================================================");
        System.out.println("Relation Name       : " + data.relationName());
        System.out.println("Total Instances     : " + data.numInstances());
        System.out.println("Total Attributes    : " + data.numAttributes());
        System.out.println("Class Attribute     : " + data.classAttribute().name() + " (Index: " + data.classIndex() + ")");

        // Missing values check
        int missing = checkMissingValues(data);
        System.out.println("Missing Values      : " + missing + " (" + (missing == 0 ? "PASSED - Clean dataset" : "WARNING - Imputation required") + ")");

        // Class distribution
        Attribute classAttr = data.classAttribute();
        int[] classCounts = new int[classAttr.numValues()];
        for (int i = 0; i < data.numInstances(); i++) {
            int classValIndex = (int) data.instance(i).classValue();
            classCounts[classValIndex]++;
        }

        System.out.println("\nClass Distribution:");
        for (int i = 0; i < classAttr.numValues(); i++) {
            String valueName = classAttr.value(i);
            String label = valueName.equals("1") ? "LEGITIMATE" : (valueName.equals("-1") ? "PHISHING" : "UNKNOWN");
            double pct = ((double) classCounts[i] / data.numInstances()) * 100.0;
            System.out.printf("  Value '%s' [%-10s] : %5d instances (%.2f%%)\n", valueName, label, classCounts[i], pct);
        }

        System.out.println("=================================================\n");
    }

    /**
     * Standalone main method to test DatasetLoader independently.
     */
    public static void main(String[] args) {
        System.out.println("Testing DatasetLoader independently...\n");
        try {
            Instances data = DatasetLoader.loadDataset();
            DatasetLoader.printDatasetSummary(data);
            System.out.println("DatasetLoader test PASSED successfully!");
        } catch (Exception e) {
            System.err.println("DatasetLoader test FAILED: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
