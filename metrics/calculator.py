from database.sqlite_db import SQLiteDB
from termcolor import colored
from sklearn.metrics import confusion_matrix
from typing import Tuple, List
from os import path
from math import sqrt

class Calculator:
    name = "MetricsCalculator"
    # will save the tp, tn, fp and fn for each tool in this dict
    metrics = {}
    def __init__(self, output_dir: str):
        self.db = SQLiteDB(output_dir)
        self.results_file = path.join(output_dir, 'results.txt')

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)

        with open(self.results_file, 'a') as results:
            results.write(f"[{self.name}] {green_txt} {normal_txt}\n")


    def get_labels_list(self, tool) -> Tuple[List, List]:
        """
        parses the labels from the db and returns actual and predicted labels list
        :param tool: the tool we wanna retrieve the labels of. can be either slips or suricata.
        :return: a tuple with 2 lists, first is actual, second is predicted
        """
        actual = []
        predicted = []

        # get all the ground truth labels
        for flow in self.db.get_labeled_flows_by('ground_truth'):
            # each flow looks something like this
            # ('1:Vdr6nTTZvru6dIeEb/SYh9dxtCI=', 'benign', None, None)
            aid, ground_truth_label, slips_label, suricata_label = flow
            actual.append(ground_truth_label)
            # this is important. if any of the tools have no label for a specific flow, we consider it as benign
            if tool == 'slips':
                predicted.append(slips_label)
            elif tool =='suricata':
                predicted.append(suricata_label)
        return (actual, predicted)

    def clean_labels(self, labels: list)-> list:
        """
        replaces all the None values with 'benign'
        :return: returns the given list with all the None values replaced with benign
        """

        for idx, label in enumerate(labels):
            if label is None:
                labels[idx] = 'benign'
        return labels

    def get_confusion_matrix(self, tool:str):
        """
        prints the FP, FN, TP, TN of the given tool compared with the ground truth
        :param tool: 'slips' or 'suricata'
        """
        assert tool in ['slips', 'suricata'], f'Trying to get FP rate of invalid tool: {tool}'

        actual, predicted = self.get_labels_list(tool)

        actual: list = self.clean_labels(actual)
        predicted: list = self.clean_labels(predicted)

        # the order of labels is Negative, Positive respectively.
        cm = confusion_matrix(actual, predicted, labels=['benign', 'malicious'])
        # extract TP, TN, FP, FN from the confusion matrix
        tp = cm[1, 1]
        tn = cm[0, 0]
        fp = cm[0, 1]
        fn = cm[1, 0]

        self.log(f"{tool}: True Positives (TP): ", tp)
        self.log(f"{tool}: True Negatives (TN): ", tn)
        self.log(f"{tool}: False Positives (FP): ", fp)
        self.log(f"{tool}: False Negatives (FN): ", fn)
        print()
        # will use them later
        self.metrics[tool] = {
            'TP': tp,
            'TN': tn,
            'FP': fp,
            'FN': fn
        }
        self.db.store_confusion_matrix(tool, self.metrics[tool])

    def MCC(self, tool: str):
        """
        Calculates the Matthews correlation coefficient (MCC) for a given tool
        :param tool: 'slips' or 'suricata'
        """
        numerator = self.metrics[tool]['TP'] * self.metrics[tool]['TN'] \
                    - self.metrics[tool]['FP'] * self.metrics[tool]['FN']

        denominator = sqrt(
            (self.metrics[tool]['TP'] + self.metrics[tool]['FP'])
            * (self.metrics[tool]['TP'] + self.metrics[tool]['FN'])
            * (self.metrics[tool]['TN'] + self.metrics[tool]['FP'])
            * (self.metrics[tool]['TN'] + self.metrics[tool]['FN'])
        )

        if denominator == 0:
            mcc = 'none'
        else:
            mcc = numerator / denominator

        return  mcc



    def recall(self, tool: str):
        """
        prints the recall of the given tool compared with the ground truth
        :param tool: 'slips' or 'suricata'
        """
        # make sure we have the fp and tn of this store calculated already
        if  tool not in self.metrics:
            self.get_confusion_matrix(tool)

        if self.metrics[tool]['TP'] + self.metrics[tool]['FN'] == 0:
            self.log(f"Can't get recall of {tool} because TP+FN of {tool} is: "," 0")
            recall = 0
        else:
            recall = self.metrics[tool]['TP']/(self.metrics[tool]['TP'] + self.metrics[tool]['FN'])

        self.metrics[tool].update({'recall': recall})
        self.log(f"{tool}: recall: ", recall)
        return recall


    def precision(self, tool: str):
        """
        prints the precision of the given tool compared with the ground truth
        :param tool: 'slips' or 'suricata'
        """
        # make sure we have the fp and tn of this store calculated already
        if  tool not in self.metrics:
            self.get_confusion_matrix(tool)

        if self.metrics[tool]['TP'] + self.metrics[tool]['FP'] == 0:
            precision = 0
        else:
            precision = self.metrics[tool]['TP']/(self.metrics[tool]['TP'] + self.metrics[tool]['FP'])


        self.metrics[tool].update({'precision': precision})
        self.log(f"{tool}: precision: ", precision)
        return precision

    def F1(self, tool):
        """
        prints the F1 of the given tool
        :param tool: 'slips' or 'suricata'
        """
        if tool not in self.metrics:
            self.get_confusion_matrix(tool)


        precision = self.metrics[tool]['precision']
        recall = self.metrics[tool]['recall']
        if precision + recall == 0:
            f1 = 0
        else:
            f1 = (2 * precision * recall) / (precision + recall)

        self.log(f"{tool}: F1: ", f1)
        return f1



    def FPR(self, tool, log=True) -> float:
        """
        prints the false positive rate of a given tool
        :param tool: slips or suricata
        :param log: logs the output to cli if set to true, we set it to false when we're using this function inside another one
        :return: float
        """
        # make sure we have the fp and tn of this store calculated already
        if not tool in self.metrics:
            self.get_confusion_matrix(tool)

        if self.metrics[tool]['FP'] + self.metrics[tool]['TN'] == 0:
            fpr = 'none'
        else:
            fpr = self.metrics[tool]['FP']/(self.metrics[tool]['FP'] + self.metrics[tool]['TN'])

        if log:
            self.log(f"{tool}: FPR: ", fpr)

        return fpr

    def TPR(self, tool, log=True):
        """
        TPR = TP / (TP + FN)
        prints the true positive rate of a given tool
        :param tool: slips or suricata
        :param log: logs the output to cli if set to true, we set it to false when we're using this function inside another one
        :return: float
        """
        if self.metrics[tool]['TP'] + self.metrics[tool]['FN'] == 0:
            tpr = 0
        else:
            tpr = self.metrics[tool]['TP'] / (self.metrics[tool]['TP'] + self.metrics[tool]['FN'])
        if log:
            self.log(f"{tool}: TPR: ", tpr)
        return tpr

    def FNR(self, tool):
        """
        FNR = 1- TPR
        prints the false negative rate of a given tool
        :param tool: slips or suricata
        :return: float
        """
        fnr = 1 - self.TPR(tool, log=False)
        self.log(f"{tool}: FNR: ", fnr)
        return fnr

    def TNR(self, tool, log=True):
        """
        FNR = 1 − FPR
        prints the true negative rate of a given tool
        :param tool: slips or suricata
        :param log: logs the output to cli if set to true, we set it to false when we're using this function inside another one
        :return: float
        """
        tnr = 1 - self.FPR(tool, log=False)
        if log:
            self.log(f"{tool}: TNR: ", tnr)
        return tnr



    def accuracy(self, tool):
        """
        :param tool: slips or suricata
        :return: float
        """
        numerator = self.metrics[tool]['TP'] + \
                    self.metrics[tool]['TN']

        denominator = self.metrics[tool]['TP'] + \
                      self.metrics[tool]['TN'] + \
                      self.metrics[tool]['FP'] + \
                      self.metrics[tool]['FN']
        if denominator == 0:
            acc = 'none'
        else:
            acc = numerator / denominator
        self.log(f"{tool}: Accuracy: ", acc)
        return acc

    def __del__(self):
        self.db.close()