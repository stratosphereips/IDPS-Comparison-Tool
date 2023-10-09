from typing import Tuple, List
from abstracts.comparison_methods import ComparisonMethod
from metrics.calculator import Calculator
from typing import Iterator

class FlowByFlow(ComparisonMethod):
    """
    responsible for grouping helper methods used for flow by flow comparison of tools
    """
    name = "Flow By Flow"
    supported_tools = ('slips', 'suricata')

    def init(self):
        ...

    def handle_flow_by_flow_comparison(self):
        self.log('', "-" * 30)
        self.log("Comparison method: ", self.name)
        self.log(' ', ' ')

        # now apply this method to all supported tools
        for tool in self.supported_tools:
            # get the actual and predicted labels by the tool
            calc = Calculator(tool, self.output_dir)

            labels: Iterator = self.get_labels(tool)
            cm: dict = calc.get_confusion_matrix(labels)
            self.db.store_performance_errors_flow_by_flow(tool, cm)
            calc.calc_all_metrics()
            self.log(' ', ' ')

    def get_labels(self, tool: str):
        """
        yields the actual and predicted labels for each flow stored in the db
        :return: an iterator for all the flows' labels
        """
        # get the ground truth labels and the given tools' labels for all flows
        for flow in self.db.get_labels_flow_by_flow(by=tool):
            # each flow is a tuple
            yield flow
