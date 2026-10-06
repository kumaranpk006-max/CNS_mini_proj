package com.phishingdetector;

import weka.core.Instances;
import weka.core.converters.ArffLoader;
import java.io.File;

/**
 * Phase 3 Verification Program
 * Verifies that:
 * 1. Java runtime is functional.
 * 2. Weka library is correctly resolved and loaded on classpath.
 * 3. Weka's ArffLoader can read and parse 'dataset/Training Dataset.arff'.
 */
public class TestSetup {

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println("PHASE 3 VERIFICATION: JAVA + WEKA ENVIRONMENT");
        System.out.println("=================================================");
        System.out.println("Java Version : " + System.getProperty("java.version"));
        System.out.println("Java Vendor  : " + System.getProperty("java.vendor"));
        System.out.println("OS Name      : " + System.getProperty("os.name"));
        System.out.println("User Dir     : " + System.getProperty("user.dir"));

        File arffFile = new File("dataset/Training Dataset.arff");
        System.out.println("\nChecking ARFF dataset path: " + arffFile.getAbsolutePath());

        if (!arffFile.exists()) {
            System.err.println("ERROR: Dataset file not found at " + arffFile.getAbsolutePath());
            System.exit(1);
        }

        try {
            System.out.println("Loading dataset using Weka ArffLoader...");
            ArffLoader loader = new ArffLoader();
            loader.setFile(arffFile);
            Instances data = loader.getDataSet();

            System.out.println("\nSUCCESS: Dataset successfully loaded into Weka Instances!");
            System.out.println("Relation Name       : " + data.relationName());
            System.out.println("Number of Attributes: " + data.numAttributes());
            System.out.println("Number of Instances : " + data.numInstances());

            // Set class index to the last attribute (Result)
            data.setClassIndex(data.numAttributes() - 1);
            System.out.println("Class Attribute     : " + data.classAttribute().name());
            System.out.println("Class Values Count  : " + data.classAttribute().numValues());

            System.out.println("\nVERIFICATION COMPLETE: Java + Maven + Weka setup is 100% operational.");
            System.out.println("=================================================");
        } catch (Exception e) {
            System.err.println("ERROR during Weka dataset loading: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
