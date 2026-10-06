package com.phishingdetector;

import weka.classifiers.Evaluation;
import weka.classifiers.trees.RandomForest;
import weka.core.Instances;
import weka.core.SerializationHelper;
import weka.core.converters.ArffSaver;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * ModelTrainer
 * Responsible for:
 * 1. Loading the dataset via DatasetLoader.
 * 2. Splitting into 80% Train / 20% Test via DataPreprocessor.
 * 3. Initializing and training Weka's RandomForest classifier.
 * 4. Evaluating model performance on unseen test data.
 * 5. Saving the trained model to 'model/phishing_model.model'.
 * 6. Saving the evaluation report to 'results/model_evaluation.txt'.
 */
public class ModelTrainer {

    public static final String DEFAULT_MODEL_DIR = "model";
    public static final String DEFAULT_MODEL_FILE = "model/phishing_model.model";
    public static final String DEFAULT_HEADER_FILE = "model/model_header.arff";
    public static final String DEFAULT_RESULTS_DIR = "results";
    public static final String DEFAULT_EVAL_FILE = "results/model_evaluation.txt";

    public static final int NUM_TREES = 100;
    public static final int RANDOM_SEED = 42;

    /**
     * Container holding the trained classifier, header structure, and evaluation metrics.
     */
    public static class TrainingOutput {
        public final RandomForest model;
        public final Instances header;
        public final Evaluation evaluation;
        public final double accuracy;

        public TrainingOutput(RandomForest model, Instances header, Evaluation evaluation, double accuracy) {
            this.model = model;
            this.header = header;
            this.evaluation = evaluation;
            this.accuracy = accuracy;
        }
    }

    /**
     * Executes the complete training and evaluation pipeline.
     *
     * @return TrainingOutput containing trained model and evaluation.
     * @throws Exception If loading, training, or saving fails.
     */
    public static TrainingOutput train() throws Exception {
        System.out.println("=================================================");
        System.out.println("     PHASE 6: RANDOM FOREST MODEL TRAINING      ");
        System.out.println("=================================================");

        // 1. Load Dataset
        Instances data = DatasetLoader.loadDataset();

        // 2. Partition into 80% Train / 20% Test with fixed seed (42)
        DataPreprocessor.TrainTestSplit split = DataPreprocessor.splitDataset(data);
        Instances trainSet = split.getTrainSet();
        Instances testSet = split.getTestSet();

        // 3. Configure Random Forest
        System.out.println("\n[ModelTrainer] Configuring RandomForest classifier...");
        System.out.println("  - Number of Trees (Iterations) : " + NUM_TREES);
        System.out.println("  - Random Seed                  : " + RANDOM_SEED);
        System.out.println("  - Execution Slots (CPU Cores)  : All available");

        RandomForest rf = new RandomForest();
        rf.setNumIterations(NUM_TREES);
        rf.setSeed(RANDOM_SEED);
        rf.setNumExecutionSlots(0); // Utilize all CPU cores

        // 4. Train Random Forest
        System.out.println("\n[ModelTrainer] Training RandomForest on " + trainSet.numInstances() + " instances...");
        long startTime = System.currentTimeMillis();
        rf.buildClassifier(trainSet);
        long trainTime = System.currentTimeMillis() - startTime;
        System.out.printf("[ModelTrainer] Model training completed in %.2f seconds.\n", trainTime / 1000.0);

        // 5. Evaluate on Unseen Test Set
        System.out.println("\n[ModelTrainer] Evaluating model on " + testSet.numInstances() + " unseen test instances...");
        Evaluation eval = new Evaluation(trainSet);
        eval.evaluateModel(rf, testSet);

        double accuracy = eval.pctCorrect();
        System.out.printf("[ModelTrainer] Test Evaluation Accuracy: %.2f%%\n", accuracy);

        // 6. Save Model and Model Header
        saveModel(rf, trainSet, DEFAULT_MODEL_FILE, DEFAULT_HEADER_FILE);

        // 7. Generate and Save Detailed Evaluation Report
        generateAndSaveEvaluationReport(eval, trainSet, testSet, trainTime, DEFAULT_EVAL_FILE);

        System.out.println("=================================================");
        System.out.println("          MODEL TRAINING SUCCESSFUL!             ");
        System.out.println("=================================================");

        Instances header = new Instances(trainSet, 0);
        return new TrainingOutput(rf, header, eval, accuracy);
    }

    /**
     * Serializes and saves the trained model and dataset header to disk.
     */
    public static void saveModel(RandomForest model, Instances trainSet, String modelPath, String headerPath) throws Exception {
        File modelDir = new File(DEFAULT_MODEL_DIR);
        if (!modelDir.exists()) {
            modelDir.mkdirs();
        }

        File modelFile = new File(modelPath);
        System.out.println("\n[ModelTrainer] Saving trained model to: " + modelFile.getAbsolutePath());
        SerializationHelper.write(modelFile.getAbsolutePath(), model);
        System.out.println("[ModelTrainer] Model saved successfully (Size: " + (modelFile.length() / 1024) + " KB).");

        // Save empty header template (0 instances) for fast schema validation during prediction
        File headerFile = new File(headerPath);
        System.out.println("[ModelTrainer] Saving model header template to: " + headerFile.getAbsolutePath());
        Instances header = new Instances(trainSet, 0);
        ArffSaver saver = new ArffSaver();
        saver.setInstances(header);
        saver.setFile(headerFile);
        saver.writeBatch();
        System.out.println("[ModelTrainer] Model header saved successfully.");
    }

    /**
     * Generates a comprehensive evaluation report and writes it to file and console.
     */
    public static void generateAndSaveEvaluationReport(Evaluation eval, Instances trainSet, Instances testSet, 
                                                      long trainTimeMs, String reportPath) throws Exception {
        File resultsDir = new File(DEFAULT_RESULTS_DIR);
        if (!resultsDir.exists()) {
            resultsDir.mkdirs();
        }

        StringBuilder sb = new StringBuilder();
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        sb.append("================================================================================\n");
        sb.append("          AI-BASED PHISHING URL DETECTION SYSTEM - MODEL EVALUATION             \n");
        sb.append("================================================================================\n");
        sb.append("Generated On          : ").append(timestamp).append("\n");
        sb.append("Algorithm             : Random Forest (Weka 3.8.6)\n");
        sb.append("Dataset               : Training Dataset.arff (UCI Phishing Websites Benchmark)\n");
        sb.append("Total Dataset Size    : ").append(trainSet.numInstances() + testSet.numInstances()).append(" instances\n");
        sb.append("Training Partition    : ").append(trainSet.numInstances()).append(" instances (80.00%)\n");
        sb.append("Testing Partition     : ").append(testSet.numInstances()).append(" instances (20.00%)\n");
        sb.append("Number of Trees       : ").append(NUM_TREES).append("\n");
        sb.append("Random Seed           : ").append(RANDOM_SEED).append("\n");
        sb.append(String.format("Training Duration     : %.2f seconds\n", trainTimeMs / 1000.0));
        sb.append("--------------------------------------------------------------------------------\n\n");

        sb.append("1. OVERALL PERFORMANCE METRICS (ON UNSEEN TEST DATA)\n");
        sb.append("--------------------------------------------------------------------------------\n");
        sb.append(String.format("  Correctly Classified Instances   : %-6.0f (%.4f%%)\n", eval.correct(), eval.pctCorrect()));
        sb.append(String.format("  Incorrectly Classified Instances : %-6.0f (%.4f%%)\n", eval.incorrect(), eval.pctIncorrect()));
        sb.append(String.format("  Kappa Statistic                  : %.4f\n", eval.kappa()));
        sb.append(String.format("  Mean Absolute Error (MAE)        : %.4f\n", eval.meanAbsoluteError()));
        sb.append(String.format("  Root Mean Squared Error (RMSE)   : %.4f\n", eval.rootMeanSquaredError()));
        sb.append(String.format("  Weighted Precision               : %.4f\n", eval.weightedPrecision()));
        sb.append(String.format("  Weighted Recall                  : %.4f\n", eval.weightedRecall()));
        sb.append(String.format("  Weighted F-Measure               : %.4f\n", eval.weightedFMeasure()));
        sb.append(String.format("  Weighted Area Under ROC (ROC-AUC): %.4f\n", eval.weightedAreaUnderROC()));
        sb.append(String.format("  Weighted Area Under PR (PR-AUC)  : %.4f\n\n", eval.weightedAreaUnderPRC()));

        sb.append("2. DETAILED ACCURACY BY CLASS\n");
        sb.append("--------------------------------------------------------------------------------\n");
        sb.append(String.format("%-15s %-12s %-10s %-10s %-10s %-10s %-10s\n",
                "Class Label", "Value", "Precision", "Recall", "F-Measure", "ROC-AUC", "Instances"));
        sb.append("--------------------------------------------------------------------------------\n");

        for (int i = 0; i < trainSet.classAttribute().numValues(); i++) {
            String valStr = trainSet.classAttribute().value(i);
            String label = valStr.equals("1") ? "LEGITIMATE" : (valStr.equals("-1") ? "PHISHING" : "UNKNOWN");
            int count = (int) (eval.confusionMatrix()[i][0] + eval.confusionMatrix()[i][1]);
            sb.append(String.format("%-15s %-12s %-10.4f %-10.4f %-10.4f %-10.4f %-10d\n",
                    label, valStr, eval.precision(i), eval.recall(i), eval.fMeasure(i), eval.areaUnderROC(i), count));
        }
        sb.append("--------------------------------------------------------------------------------\n\n");

        sb.append("3. CONFUSION MATRIX\n");
        sb.append("--------------------------------------------------------------------------------\n");
        double[][] matrix = eval.confusionMatrix();
        sb.append("   a      b   <-- Classified as\n");
        sb.append(String.format(" %5.0f  %5.0f | a = %s (Value '%s')\n",
                matrix[0][0], matrix[0][1],
                trainSet.classAttribute().value(0).equals("-1") ? "PHISHING" : "LEGITIMATE",
                trainSet.classAttribute().value(0)));
        sb.append(String.format(" %5.0f  %5.0f | b = %s (Value '%s')\n\n",
                matrix[1][0], matrix[1][1],
                trainSet.classAttribute().value(1).equals("1") ? "LEGITIMATE" : "PHISHING",
                trainSet.classAttribute().value(1)));

        // Interpretation of Confusion Matrix
        int tp = (int) matrix[0][0]; // Phishing correctly predicted as Phishing
        int fn = (int) matrix[0][1]; // Phishing wrongly predicted as Legitimate
        int fp = (int) matrix[1][0]; // Legitimate wrongly predicted as Phishing
        int tn = (int) matrix[1][1]; // Legitimate correctly predicted as Legitimate

        sb.append("4. CONFUSION MATRIX INTERPRETATION (CYBERSECURITY CONTEXT)\n");
        sb.append("--------------------------------------------------------------------------------\n");
        sb.append(String.format("  • True Positives  (Phishing correctly flagged)      : %d\n", tp));
        sb.append(String.format("  • True Negatives  (Legitimate correctly permitted) : %d\n", tn));
        sb.append(String.format("  • False Positives (Legitimate wrongly flagged)      : %d (Inconvenience to user)\n", fp));
        sb.append(String.format("  • False Negatives (Phishing missed - HIGH RISK)    : %d (Critical security risk)\n\n", fn));
        sb.append("CYBERSECURITY NOTE: In phishing detection, False Negatives (FN) are significantly\n");
        sb.append("more dangerous than False Positives (FP). A false negative allows a phishing attack\n");
        sb.append("to evade detection, potentially exposing users to credential theft or malware.\n");
        sb.append("================================================================================\n");

        // Write to file
        File evalFile = new File(reportPath);
        try (PrintWriter writer = new PrintWriter(new FileWriter(evalFile))) {
            writer.print(sb.toString());
        }
        System.out.println("\n[ModelTrainer] Detailed evaluation saved to: " + evalFile.getAbsolutePath());

        // Also print summary to console
        System.out.println(sb.toString());
    }

    /**
     * Standalone main method to train and evaluate the model.
     */
    public static void main(String[] args) {
        try {
            ModelTrainer.train();
        } catch (Exception e) {
            System.err.println("ModelTrainer FAILED: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
