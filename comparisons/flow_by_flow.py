from typing import Tuple, List
from database.sqlite_db import SQLiteDB

class FlowByFlow:
    """
    responsible for grouping helper methods used for flow by flow comparison of tools
    """
    name = "Flow By Flow"
    def __init__(self, output_dir):
        self.db = SQLiteDB(output_dir)

    def get_labels_lists(self, tool: str) -> Tuple[List, List]:
        """
        parses the labels from the db and returns actual and predicted labels list for the given tool
        :return: a tuple with 2 lists, first is actual, second is predicted labels
        """
        actual = []
        predicted = []

        # get all the ground truth labels
        for flow in self.db.get_labeled_flows_by('ground_truth'):
            # todo do this with a query!

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