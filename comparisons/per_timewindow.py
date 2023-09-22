from typing import Tuple, List
from database.sqlite_db import SQLiteDB
from abstracts.comparison_methods import ComparisonMethod


class PerTimewindow(ComparisonMethod):
    """
    responsible for grouping helper methods used for timewindow comparison of tools
    """
    name = "Per Timewindow"
    def init(self):
        self.last_registered_tw: int = self.db.get_last_registered_timewindow()

    def print_stats(self):
        self.log(f"Total registered timewindows by the ground truth: "
                 f"{self.last_registered_tw+ 1}. "
                 f"from 0-{self.last_registered_tw}")

    def print_total(self, actual:list, predicted:list, tool: str,  label: str):
        """
        prints the number of actual and predicted timewindow labels compared with the ground truth
        """
        # total registered tws
        tot_tws: int = self.db.get_last_registered_timewindow() +1

        predicted_count = predicted.count(label)
        actual_count = actual.count(label)

        self.log(f"Total timeinwodws seen in the ground truth (malicious+benign): ",
                 tot_tws)
        self.log(f"Total timewindows detected by {tool} as {label}: ",
                 predicted_count)
        self.log(f"Actual {label} timewindows found in the grount truth:",
                 actual_count)

    def get_labels_lists(self, tool: str) -> Tuple[List, List]:
        """
        parses the labels from the db and returns actual and predicted labels list for the given tool
        :return: a tuple with 2 lists, first is actual, second is predicted labels
        """
        actual = []
        predicted = []

        for tw in range(self.last_registered_tw +1):
            for row in self.db.get_labels_per_tw(tw, by=tool):

                # each row  looks like this:
                # ('192.168.1.109', '6', 'benign', 'benign')
                IP, timewindow, gt_label, tool_label = row

                # Each detection per TW is represented by 1 label in the actual and 1 label in the predicted list
                # if 1 IP is detected in 7 tws, this detection will be represented by 7 different values in
                # the actual and predicted lists
                predicted.append(tool_label)
                actual.append(gt_label)

        self.print_total(actual, predicted, tool, 'malicious')
        self.print_total(actual, predicted, tool, 'benign')
        print()

        return (actual, predicted)