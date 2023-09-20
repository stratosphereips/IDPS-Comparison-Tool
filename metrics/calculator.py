from database.sqlite_db import SQLiteDB
from termcolor import colored
from sklearn.metrics import confusion_matrix
from os import path
from math import sqrt

class Calculator:
    name = "MetricsCalculator"
    # will save the tp, tn, fp and fn for each tool in this dict
    metrics = {}
    
    def __init__(self,
                 tool,
                 actual_labels:list,
                 predicted_labels: list,
                 output_dir: str
                 ):
        self.db = SQLiteDB(output_dir)
        self.results_file = path.join(output_dir, 'results.txt')
        assert tool in ['slips', 'suricata'], f'Trying to get metrics of an invalid tool: {tool}'
        self.tool = tool
        self.actual_labels = actual_labels
        self.predicted_labels = predicted_labels

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)

        with open(self.results_file, 'a') as results:
            results.write(f"[{self.name}] {green_txt} {normal_txt}\n")


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
        """

        actual: list = self.clean_labels(self.actual_labels)
        predicted: list = self.clean_labels(self.predicted_labels)

        # the order of labels is Negative, Positive respectively.
        cm = confusion_matrix(actual, predicted, labels=['benign', 'malicious'])
        # extract TP, TN, FP, FN from the confusion matrix
        tp = cm[1, 1]
        tn = cm[0, 0]
        fp = cm[0, 1]
        fn = cm[1, 0]

        self.log(f"{self.tool}: True Positives (TP): ", tp)
        self.log(f"{self.tool}: True Negatives (TN): ", tn)
        self.log(f"{self.tool}: False Positives (FP): ", fp)
        self.log(f"{self.tool}: False Negatives (FN): ", fn)
        print()
        
        # will use them later
        self.metrics[self.tool] = {
            'TP': tp,
            'TN': tn,
            'FP': fp,
            'FN': fn
        }
        self.db.store_confusion_matrix(self.tool, self.metrics[self.tool])

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
            mcc = 'none'
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
            fpr = 'none'
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
            acc = 'none'
        else:
            acc = numerator / denominator
        self.log(f"{self.tool}: Accuracy: ", acc)
        return acc

    def __del__(self):
        self.db.close()