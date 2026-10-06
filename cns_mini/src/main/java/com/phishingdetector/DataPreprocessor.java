package com.phishingdetector;

import weka.core.Instances;

import java.util.Random;

/**
 * DataPreprocessor
 * Handles dataset preprocessing, validation, and reproducible train-test splitting.
 * Avoids unnecessary transformations (like feature scaling) that are not needed
 * for Random Forest on discrete nominal features.
 */
public class DataPreprocessor {

    public static final double DEFAULT_TRAIN_RATIO = 0.80; // 80% Training
    public static final long DEFAULT_RANDOM_SEED = 42L;    // Fixed seed for reproducibility

    /**
     * Container holding partitioned training and testing Instances.
     */
    public static class TrainTestSplit {
        private final Instances trainSet;
        private final Instances testSet;

        public TrainTestSplit(Instances trainSet, Instances testSet) {
            this.trainSet = trainSet;
            this.testSet = testSet;
        }

        public Instances getTrainSet() {
            return trainSet;
        }

        public Instances getTestSet() {
            return testSet;
        }
    }

    /**
     * Performs a stratified, randomized train-test split on the dataset.
     * Uses a fixed seed (42) for scientific reproducibility.
     *
     * @param data Full dataset with class index set.
     * @param trainRatio Proportion for training (e.g. 0.80 for 80%).
     * @param seed Random seed for shuffling.
     * @return TrainTestSplit containing training set and testing set.
     */
    public static TrainTestSplit splitDataset(Instances data, double trainRatio, long seed) {
        if (data.classIndex() < 0) {
            throw new IllegalStateException("Class index must be set before splitting dataset.");
        }

        System.out.printf("[DataPreprocessor] Splitting dataset (%d instances) -> %.0f%% Train / %.0f%% Test (Seed: %d)...\n",
                data.numInstances(), trainRatio * 100.0, (1.0 - trainRatio) * 100.0, seed);

        // Stratify the dataset (preserves class distribution across splits)
        Instances workingCopy = new Instances(data);
        Random random = new Random(seed);
        workingCopy.randomize(random);

        if (workingCopy.classAttribute().isNominal()) {
            workingCopy.stratify(10); // Standard 10-fold stratification basis
        }

        int trainSize = (int) Math.round(workingCopy.numInstances() * trainRatio);
        int testSize = workingCopy.numInstances() - trainSize;

        Instances trainData = new Instances(workingCopy, 0, trainSize);
        Instances testData = new Instances(workingCopy, trainSize, testSize);

        System.out.printf("[DataPreprocessor] Training instances: %d (%.2f%%)\n",
                trainData.numInstances(), ((double) trainData.numInstances() / workingCopy.numInstances()) * 100.0);
        System.out.printf("[DataPreprocessor] Testing instances : %d (%.2f%%)\n",
                testData.numInstances(), ((double) testData.numInstances() / workingCopy.numInstances()) * 100.0);

        return new TrainTestSplit(trainData, testData);
    }

    /**
     * Splits dataset with default 80/20 ratio and seed 42.
     */
    public static TrainTestSplit splitDataset(Instances data) {
        return splitDataset(data, DEFAULT_TRAIN_RATIO, DEFAULT_RANDOM_SEED);
    }

    /**
     * Standalone main method to test DataPreprocessor independently.
     */
    public static void main(String[] args) {
        System.out.println("Testing DataPreprocessor independently...\n");
        try {
            Instances data = DatasetLoader.loadDataset();
            TrainTestSplit split = DataPreprocessor.splitDataset(data);

            System.out.println("\nChecking class distribution in Training Set:");
            DatasetLoader.printDatasetSummary(split.getTrainSet());

            System.out.println("Checking class distribution in Testing Set:");
            DatasetLoader.printDatasetSummary(split.getTestSet());

            System.out.println("DataPreprocessor test PASSED successfully!");
        } catch (Exception e) {
            System.err.println("DataPreprocessor test FAILED: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
