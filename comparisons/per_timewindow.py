from typing import Tuple, List
from database.sqlite_db import SQLiteDB
from abstracts.abstracts import ComparisonMethod


class PerTimewindow(ComparisonMethod):
    """
    responsible for grouping helper methods used for timewindow comparison of tools
    """
    name = "Per Timewindow"
    def init(self):
        self.print_stats()

    def print_stats(self):
        ...

    def get_labels_lists(self, tool: str) -> Tuple[List, List]:
        """
        parses the labels from the db and returns actual and predicted labels list for the given tool
        :return: a tuple with 2 lists, first is actual, second is predicted labels
        """
        actual = []
        predicted = []

        last_registered_tw: int = self.db.get_last_registered_timewindow()

        for tw in range(last_registered_tw +1):
            for row in self.db.get_labels_per_tw(tw, by=tool):

                # each row  looks like this:
                # ('192.168.1.109', '6', 'benign', 'benign')
                IP, timewindow, gt_label, tool_label = row

                # Each detection per TW is represented by 1 label in the actual and 1 label in the predicted list
                # if 1 IP is detected in 7 tws, this detection will be represented by 7 different values in
                # the actual and predicted lists
                predicted.append(tool_label)
                actual.append(gt_label)

        return (actual, predicted)