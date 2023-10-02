from typing import Tuple, List
from abstracts.comparison_methods import ComparisonMethod


class FlowByFlow(ComparisonMethod):
    """
    responsible for grouping helper methods used for flow by flow comparison of tools
    """
    name = "Flow By Flow"
    def init(self):
        ...

    def get_labels(self, tool: str) -> Tuple[List, List]:
        """
        yields the actual and predicted labels for each flow stored in the db
        :return: an iterator for all the flows' labels
        """
        # get the ground truth labels and the given tools' labels for all flows
        for flow in self.db.get_labels_flow_by_flow(by=tool):
            # each flow is a tuple
            ground_truth_label, tool_label = flow
            yield ground_truth_label, tool_label
