import pytest

from metrics.calculator import Calculator

class TestCalculator:

    def setup_class(self):
        self.calculator = Calculator(
            tool='slips',
            actual_labels=['malicious', 'benign', 'malicious', 'benign'],
            predicted_labels=['malicious', 'malicious', 'benign', 'malicious'],
            output_dir='output'
        )
        x = self.calculator.get_confusion_matrix()

    def teardown_class(self):
        self.calculator.db.close()

    def test_get_confusion_matrix(self):
        """
        Test that the `get_confusion_matrix()` method returns the correct confusion matrix.
        """

        expected_confusion_matrix = {'TP': 1, 'TN': 0, 'FP': 2, 'FN': 1}
        actual_confusion_matrix = self.calculator.get_confusion_matrix()
        assert expected_confusion_matrix == actual_confusion_matrix

    def test_MCC(self):
        """
        Test that the `MCC()` method calculates the Matthews correlation coefficient correctly.
        """

        expected_mcc = -0.5773502691896258
        actual_mcc = self.calculator.MCC()

        assert expected_mcc == actual_mcc

    def test_recall(self):
        """
        Test that the `recall()` method calculates the recall correctly.
        """

        expected_recall = 0.5
        actual_recall = self.calculator.recall()

        assert expected_recall == actual_recall

    def test_precision(self):
        """
        Test that the `precision()` method calculates the precision correctly.
        """

        expected_precision = 0.3333333333333333
        actual_precision = self.calculator.precision()

        assert expected_precision == actual_precision

    def test_F1(self):
        """
        Test that the `F1()` method calculates the F1 score correctly.
        """

        expected_f1 = 0.4
        actual_f1 = self.calculator.F1()

        assert expected_f1 == actual_f1

    def test_FPR(self):
        """
        Test that the `FPR()` method calculates the false positive rate correctly.
        """

        expected_fpr = 1.0
        actual_fpr = self.calculator.FPR()

        assert expected_fpr == actual_fpr

    def test_TPR(self):
        """
        Test that the `TPR()` method calculates the true positive rate correctly.
        """

        expected_tpr = 0.5
        actual_tpr = self.calculator.TPR()

        assert expected_tpr == actual_tpr

    def test_FNR(self):
        """
        Test that the `FNR()` method calculates the false negative rate correctly.
        """

        expected_fnr = 0.5
        actual_fnr = self.calculator.FNR()

        assert expected_fnr == actual_fnr

    def test_TNR(self):
        """
        Test that the `TNR()` method calculates the true negative rate correctly.
        """

        expected_tnr = 0.0
        actual_tnr = self.calculator.TNR()

        assert expected_tnr == actual_tnr

    def test_accuracy(self):
        """
        Test that the `accuracy()` method calculates the accuracy correctly.
        """

        expected_accuracy = 0.25
        actual_accuracy = self.calculator.accuracy()

        assert expected_accuracy == actual_accuracy
