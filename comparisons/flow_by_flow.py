from typing import Tuple, List
from abstracts.comparison_methods import ComparisonMethod


class FlowByFlow(ComparisonMethod):
    """
    responsible for grouping helper methods used for flow by flow comparison of tools
    """
    name = "Flow By Flow"
    def init(self):
        ...

    def get_labels_lists(self, tool: str) -> Tuple[List, List]:
        """
        parses the labels from the db and returns actual and predicted labels list for the given tool
        :return: a tuple with 2 lists, first is actual, second is predicted labels
        """
        actual = []
        predicted = []

        # get the ground truth labels and the given tools' labels for all flows
        for flow in self.db.get_labels_flow_by_flow(by=tool):
            # each flow looks something like this
            # (aid, gt_label, tool_label)
            ground_truth_label, tool_label = flow
            actual.append(ground_truth_label)
            predicted.append(tool_label)

        return actual, predicted