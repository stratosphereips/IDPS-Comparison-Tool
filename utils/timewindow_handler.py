from datetime import datetime, timezone
from math import ceil

class TimewindowHandler:
    """
    Explanation of Timewindows
    if we have a pcap with the following
    starttime = 0h
    endtime = 10h
    and the width of the tw is 2h
    this is how tws would look like

    5/2 = 2.5
    0 + 2.5*5
    0+ ((given/width)*given)/width
    start + (width * ?) = given
    width * ?  = given - start
    ceil((given-start) / width)) -1


          tw0   tw1   tw2   tw3    tw4    tw5
      0 ──────┬─────┬──────┬──────┬─────┬──────
              │     │      │      │     │
              2     4      6      8     10

    a flow with ts = 7 would be in tw3
    """
    # 1h, this is the default width in slips
    # TODO we should read this from the config file?
    width = 3600
    def __init__(self, ts_of_first_flow):
        self.ts_of_first_flow = float(ts_of_first_flow)

    def get_start_and_end_ts(self, tw: int):
        """
        returns the start ts and end ts of the given timewindow
        :param tw: the tw that we wanna get the strat and end of
        """
        start = self.ts_of_first_flow + (self.width * tw )
        end = start + self.width
        return start, end

    def get_tw_of_ts(self, ts: str) -> int:
        """
        this method returns the timewindow where the given ts exists
        :param ts: str ts in unix format
        :return: int of the tw where the ts exists
        """
        tw = (ceil((float(ts)-self.ts_of_first_flow)/self.width) - 1)

        return 0 if tw * -1 < 0 else tw

