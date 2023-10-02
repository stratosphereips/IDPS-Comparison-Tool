from database.sqlite_db import SQLiteDB
from termcolor import colored
from os import path
from math import sqrt
from abstracts.observer import IObservable
from logger.logger import Logger

class Calculator(IObservable):
    name = "MetricsCalculator"
    # will save the tp, tn, fp and fn for each tool in this dict
    metrics = {}

    def __init__(self,
                 tool,
                 actual_labels:list,
                 predicted_labels: list,
                 output_dir: str
                 ):
        super(Calculator, self).__init__()

        # init the logger
        self.results_path = path.join(output_dir, 'results.txt')
        self.logger = Logger(self.name, self.results_path)
        self.add_observer(self.logger)

        self.db = SQLiteDB(output_dir)
        assert tool in ['slips', 'suricata'], f'Trying to get metrics of an invalid tool: {tool}'
        self.tool = tool
        self.actual_labels = actual_labels
        self.predicted_labels = predicted_labels

    def log(self, green_txt, normal_txt):
        self.notify_observers((normal_txt, green_txt))

    def confusion_matrix(self, actual_labels, predicted_labels):
        """
        Calculate a confusion matrix for binary classification.

        Parameters:
        - actual_labels: A list of actual labels (0 or 1).
        - predicted_labels: A list of predicted labels (0 or 1).

        Returns:
        - A dictionary containing TP, TN, FP, FN counts.
        """
        assert len(actual_labels) == len(predicted_labels), "Input lists must have the same length."

        tp, tn, fp, fn = 0, 0, 0, 0
        positive_label = 'malicious'

        for actual, predicted in zip(actual_labels, predicted_labels):
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

    def clean_labels(self, labels: list)-> list:
        """
        replaces all the None values with 'benign'
        :return: returns the given list with all the None values replaced with benign
        """

        for idx, label in enumerate(labels):
            if label is None:
                labels[idx] = 'benign'
        return labels

    def get_confusion_matrix(self):
        """
        prints the FP, FN, TP, TN of the given self.tool compared with the ground truth
        and stores them in mem for later
        """

        actual: list = self.clean_labels(self.actual_labels)
        predicted: list = self.clean_labels(self.predicted_labels)

        # the order of labels is Negative, Positive respectively.
        cm = self.confusion_matrix(actual, predicted)


        self.log(f"{self.tool}: True Positives (TP): ", cm['TP'])
        self.log(f"{self.tool}: True Negatives (TN): ", cm['TN'])
        self.log(f"{self.tool}: False Positives (FP): ", cm['FP'])
        self.log(f"{self.tool}: False Negatives (FN): ", cm['FN'])
        print()

        # will use them later
        self.metrics[self.tool] = cm
        self.db.store_confusion_matrix(self.tool, self.metrics[self.tool])
        return self.metrics[self.tool]

    def MCC(self):
        """
        Calculates the Matthews correlation coefficient (MCC) for a given tool
        """
        numerator = self.metrics[self.tool]['TP'] * self.metrics[self.tool]['TN'] \
                    - self.metrics[self.tool]['FP'] * self.metrics[self.tool]['FN']

        denominator = sqrt(
            (self.metrics[self.tool]['TP'] + self.metrics[self.tool]['FP'])
            * (self.metrics[self.tool]['TP'] + self.metrics[self.tool]['FN'])
            * (self.metrics[self.tool]['TN'] + self.metrics[self.tool]['FP'])
            * (self.metrics[self.tool]['TN'] + self.metrics[self.tool]['FN'])
        )

        if denominator == 0:
            mcc = 0
        else:
            mcc = numerator / denominator

        return  mcc

    def recall(self):
        """
        prints the recall of the given tool compared with the ground truth
        """
        # make sure we have the fp and tn of this store calculated already
        if  self.tool not in self.metrics:
            self.get_confusion_matrix()

        if self.metrics[self.tool]['TP'] + self.metrics[self.tool]['FN'] == 0:
            self.log(f"Can't get recall of {self.tool} because TP+FN of {self.tool} is: "," 0")
            recall = 0
        else:
            recall = self.metrics[self.tool]['TP']/(self.metrics[self.tool]['TP'] + self.metrics[self.tool]['FN'])

        self.metrics[self.tool].update({'recall': recall})
        self.log(f"{self.tool}: recall: ", recall)
        return recall


    def precision(self):
        """
        prints the precision of the given tool compared with the ground truth
        """
        # make sure we have the fp and tn of this store calculated already
        if  self.tool not in self.metrics:
            self.get_confusion_matrix()

        if self.metrics[self.tool]['TP'] + self.metrics[self.tool]['FP'] == 0:
            precision = 0
        else:
            precision = self.metrics[self.tool]['TP']/(self.metrics[self.tool]['TP'] + self.metrics[self.tool]['FP'])


        self.metrics[self.tool].update({'precision': precision})
        self.log(f"{self.tool}: precision: ", precision)
        return precision

    def F1(self):
        """
        prints the F1 of the given tool
        """
        if self.tool not in self.metrics:
            self.get_confusion_matrix()


        precision = self.metrics[self.tool]['precision']
        recall = self.metrics[self.tool]['recall']
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
        # make sure we have the fp and tn of this store calculated already
        if not self.tool in self.metrics:
            self.get_confusion_matrix()

        if self.metrics[self.tool]['FP'] + self.metrics[self.tool]['TN'] == 0:
            fpr = 0
        else:
            fpr = self.metrics[self.tool]['FP']/(self.metrics[self.tool]['FP'] + self.metrics[self.tool]['TN'])

        if log:
            self.log(f"{self.tool}: FPR: ", fpr)

        return fpr

    def TPR(self, log=True):
        """
        TPR = TP / (TP + FN)
        prints the true positive rate of a given tool
        :param log: logs the output to cli if set to true, we set it to false when we're using this function inside another one
        :return: float
        """
        if self.metrics[self.tool]['TP'] + self.metrics[self.tool]['FN'] == 0:
            tpr = 0
        else:
            tpr = self.metrics[self.tool]['TP'] / (self.metrics[self.tool]['TP'] + self.metrics[self.tool]['FN'])
        if log:
            self.log(f"{self.tool}: TPR: ", tpr)
        return tpr

    def FNR(self):
        """
        FNR = 1- TPR
        prints the false negative rate of a given tool
        :return: float
        """
        fnr = 1 - self.TPR(log=False)
        self.log(f"{self.tool}: FNR: ", fnr)
        return fnr

    def TNR(self, log=True):
        """
        FNR = 1 − FPR
        prints the true negative rate of a given tool
        :param log: logs the output to cli if set to true, we set it to false when we're using this function inside another one
        :return: float
        """
        tnr = 1 - self.FPR(log=False)
        if log:
            self.log(f"{self.tool}: TNR: ", tnr)
        return tnr

    def accuracy(self):
        """
        :return: float
        """
        numerator = self.metrics[self.tool]['TP'] + \
                    self.metrics[self.tool]['TN']

        denominator = self.metrics[self.tool]['TP'] + \
                      self.metrics[self.tool]['TN'] + \
                      self.metrics[self.tool]['FP'] + \
                      self.metrics[self.tool]['FN']
        if denominator == 0:
            acc = 0
        else:
            acc = numerator / denominator

        self.log(f"{self.tool}: Accuracy: ", acc)
        return acc

    def __del__(self):
        self.db.close()