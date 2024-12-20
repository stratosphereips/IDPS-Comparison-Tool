from database.sqlite_db import SQLiteDB
from termcolor import colored
from os import path
from math import sqrt
from typing import Optional, Iterator
from abstracts.observer import IObservable
from logger.logger import Logger

class Calculator(IObservable):
    name = "MetricsCalculator"
    # will save the tp, tn, fp and fn for each tool in this dict
    metrics = {}

    def __init__(
             self,
             tool: str,
             output_dir: str,
    ):
        super(Calculator, self).__init__()

        # init the logger
        self.results_path = path.join(output_dir, 'results.txt')
        self.logger = Logger(self.name, output_dir)
        self.add_observer(self.logger)

        self.db = SQLiteDB(output_dir)
        assert tool in ['slips', 'suricata'], f'Trying to get metrics of an invalid tool: {tool}'
        self.tool = tool


    def log(self, colored_txt, normal_txt, log_to_results_file=True,
            end="\n",
            error=False):
        self.notify_observers((
            normal_txt, colored_txt, log_to_results_file, end, error
            ))

    def confusion_matrix(self, labels: Iterator):
        """
        Calculate a confusion matrix for binary classification.

        Parameters:
        - actual_labels: A list of actual labels (0 or 1).
        - predicted_labels: A list of predicted labels (0 or 1).
        Returns:
        - A dictionary containing TP, TN, FP, FN counts.
        """
        positive_label = 'malicious'

        tp, tn, fp, fn = 0, 0, 0, 0

        for set_ in labels:
            actual, predicted = set_
            actual: str = self.clean_label(actual)
            predicted: str = self.clean_label(predicted)

            if not actual and not predicted:
                break

            if actual == positive_label:
                if predicted == positive_label:
                    tp += 1
                else:
                    fn += 1
            else:
                if predicted == positive_label:
                    fp += 1
                else:
                    tn += 1

        return {
            'TP': tp,
            'TN': tn,
            'FP': fp,
            'FN': fn
        }

    def clean_label(self, label: Optional[str]) -> str:
        """
        returns benign if the label is unknown
        """
        return 'benign' if label is None else label

    def log_cm(self, cm):
        self.log(f"{self.tool}: True Positives (TP): ", cm['TP'])
        self.log(f"{self.tool}: True Negatives (TN): ", cm['TN'])
        self.log(f"{self.tool}: False Positives (FP): ", cm['FP'])
        self.log(f"{self.tool}: False Negatives (FN): ", cm['FN'])
        print()

    def get_confusion_matrix(self, labels, log=True):
        """
        prints the FP, FN, TP, TN of the given self.tool compared with the ground truth
        and stores them in mem for later
        by default we're expecting the comparer.get_labels to return an interator, if not,
        :param labels: a  list of tuples [(actual, predicted)] ,, or an iterator of tuples
        """
        # labels can be a list of tuples or an iterator
        if type(labels) == list:
            labels = iter(labels)

        # the order of labels is Negative, Positive respectively.
        cm = self.confusion_matrix(labels)

        if log:
            self.log_cm(cm)

        # will use them later
        self.metrics = cm
        return cm

    def MCC(self) -> float:
        """
        Calculates the Matthews correlation coefficient (MCC) for a given tool
        """
        numerator = self.metrics['TP'] * self.metrics['TN'] \
                    - self.metrics['FP'] * self.metrics['FN']

        denominator = sqrt(
            (self.metrics['TP'] + self.metrics['FP'])
            * (self.metrics['TP'] + self.metrics['FN'])
            * (self.metrics['TN'] + self.metrics['FP'])
            * (self.metrics['TN'] + self.metrics['FN'])
        )

        if denominator == 0:
            mcc = 0
        else:
            mcc = numerator / denominator

        return  mcc

    def recall(self) -> float:
        """
        prints the recall of the given tool compared with the ground truth
        """

        if self.metrics['TP'] + self.metrics['FN'] == 0:
            # self.log(f"Can't get recall of {self.tool} because TP+FN of {self.tool} is: "," 0")
            recall = 0
        else:
            recall = self.metrics['TP']/(self.metrics['TP'] + self.metrics['FN'])

        self.metrics.update({'recall': recall})
        self.log(f"{self.tool}: recall: ", recall)
        return recall


    def precision(self) -> float:
        """
        prints the precision of the given tool compared with the ground truth
        """

        if self.metrics['TP'] + self.metrics['FP'] == 0:
            precision = 0
        else:
            precision = self.metrics['TP']/(self.metrics['TP'] + self.metrics['FP'])


        self.metrics.update({'precision': precision})
        self.log(f"{self.tool}: precision: ", precision)
        return precision

    def F1(self) -> float:
        """
        prints the F1 of the given tool
        """

        precision = self.metrics['precision']
        recall = self.metrics['recall']
        if precision + recall == 0:
            f1 = 0
        else:
            f1 = (2 * precision * recall) / (precision + recall)

        self.log(f"{self.tool}: F1: ", f1)
        return f1



    def FPR(self, log=True) -> float:
        """
        prints the false positive rate of a given tool
        :param log: logs the output to cli if set to true, we set it to false when we're using this function inside another one
        :return: float
        """

        if self.metrics['FP'] + self.metrics['TN'] == 0:
            fpr = 0
        else:
            fpr = self.metrics['FP']/(self.metrics['FP'] + self.metrics['TN'])

        if log:
            self.log(f"{self.tool}: FPR: ", fpr)

        return fpr

    def TPR(self, log=True) -> float:
        """
        TPR = TP / (TP + FN)
        prints the true positive rate of a given tool
        :param log: logs the output to cli if set to true, we set it to false when we're using this function inside another one
        :return: float
        """
        if self.metrics['TP'] + self.metrics['FN'] == 0:
            tpr = 0
        else:
            tpr = self.metrics['TP'] / (self.metrics['TP'] + self.metrics['FN'])
        if log:
            self.log(f"{self.tool}: TPR: ", tpr)
        return tpr

    def FNR(self) -> float:
        """
        FNR = FN / (FN + TP)
        prints the false negative rate of a given tool
        """
        try:
            fnr = self.metrics["FN"] / (self.metrics["FN"] + self.metrics["TP"])
        except ZeroDivisionError:
            fnr = 0

        self.log(f"{self.tool}: FNR: ", fnr)
        return fnr

    def TNR(self, log=True) -> float:
        """
        FNR = 1 − FPR
        prints the true negative rate of a given tool
        :param log: logs the output to cli if set to true, we set it to false when we're using this function inside another one
        """
        tnr = 1 - self.FPR(log=False)
        if log:
            self.log(f"{self.tool}: TNR: ", tnr)
        return tnr

    def accuracy(self) -> float:
        """
        :return: float
        """
        numerator = self.metrics['TP'] + \
                    self.metrics['TN']

        denominator = self.metrics['TP'] + \
                      self.metrics['TN'] + \
                      self.metrics['FP'] + \
                      self.metrics['FN']
        if denominator == 0:
            acc = 0
        else:
            acc = numerator / denominator

        self.log(f"{self.tool}: Accuracy: ", acc)
        return acc

    def calc_all_metrics(self):
        """
        calls all the methods in this class
        """
        for metric in (
            self.FPR,
            self.FNR,
            self.TPR,
            self.TNR,
            self.recall,
            self.precision,
            self.F1,
            self.accuracy,
            self.MCC,
        ):
            metric()

    def __del__(self):
        self.db.close()