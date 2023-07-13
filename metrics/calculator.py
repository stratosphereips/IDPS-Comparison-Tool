from database.sqlite_db import SQLiteDB
from termcolor import colored
from sklearn.metrics import confusion_matrix
import json
from typing import Tuple, List

class Calculator:
    name = "MetricsCalculator"
    def __init__(self, db: SQLiteDB):
        self.db = db

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)

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
            community_id, ground_truth_label, slips_label, suricata_label = flow
            actual.append(ground_truth_label)
            # this is important. if any of the tools have no label for a specific flow, we consider it as benign
            if tool == 'slips':
                predicted.append(slips_label)
            elif tool =='suricata':
                predicted.append(suricata_label)
        return (actual, predicted)
