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
                 f"{self.last_registered_tw+ 1}. ",
                 f"from 0-{self.last_registered_tw}")
        print()

    def get_labels(self, tool: str) -> Tuple[List, List]:
        """
        parses the labels from the db and returns actual and predicted labels list for the given tool
        :return: a tuple with 2 lists, first is actual, second is predicted labels
        """

        for tw in range(self.last_registered_tw +1):
            for row in self.db.get_labels_per_tw(tw, by=tool):
                # Each detection per TW is represented by 1 label in the actual and 1 label in the predicted list
                # if 1 IP is detected in 7 tws, this detection will be represented by 7 different values in
                yield row
        self.print_stats()


