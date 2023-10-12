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

        # now apply this method to all supported tools
        for tool in self.supported_tools:
            calc = Calculator(tool, self.output_dir)
            # stores the sum of all tps tn fp fns read calculated for each ip for each tw
            cm_sum = {
                'TP':0,
                'FP':0,
                'TN':0,
                'FN':0,
                }
            for row in  self.db.get_all_labels_per_all_tws(tool):
                # each row is (ip, tw , gt_label, tool_label)
                ip, tw , gt_label, tool_label = row

                cm: dict = calc.get_confusion_matrix([(gt_label, tool_label)], log=False)
                for metric, val in cm.items():
                    cm_sum[metric] += val

            self.db.store_performance_errors_per_tw(tool, cm_sum)
            calc.metrics = cm_sum
            calc.log_cm(calc.metrics)
            calc.calc_all_metrics()
            print()
            # todo the printed cm is wrong

        self.print_stats()


