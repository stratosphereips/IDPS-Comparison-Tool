from abstracts.comparison_methods import ComparisonMethod
from metrics.calculator import Calculator

class PerTimewindow(ComparisonMethod):
    """
    responsible for grouping helper methods used for timewindow comparison of tools
    """
    name = "Per Timewindow"
    supported_tools = ('slips', 'suricata')
    def init(self):
        self.last_registered_tw: int = self.db.get_last_registered_timewindow()


    def print_stats(self):
        self.log(f"Total registered timewindows by the ground truth: "
                 f"{self.last_registered_tw+ 1}. ",
                 f"from 0-{self.last_registered_tw}")

    def handle_per_tw_comparison(self):


        self.log('', "-" * 30)
        self.log("Comparison method: ", self.name)
        self.log(' ', ' ')
        # TODO what to log per tw?

        # now apply this method to all supported tools
        for tool in self.supported_tools:
            calc = Calculator(tool, self.output_dir)
            for row in  self.db.get_all_labels_per_all_tws(tool):
                # each row is (ip, tw , gt_label, tool_label)
                ip, tw , gt_label, tool_label = row
                cm: dict = calc.get_confusion_matrix([(gt_label, tool_label)], log=False)
                self.db.store_performance_errors_per_tw(ip, tw, tool, cm)

        self.print_stats()


