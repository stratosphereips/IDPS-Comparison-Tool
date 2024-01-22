from math import ceil

class TimewindowHandler:
    """
    Explanation of Timewindows
    if we have a pcap with the following
    starttime = 0h
    endtime = 10h
    and the width of the tw is 2h
    this is how tws would look like

    this is how we get the tw of a given_ts
    start + (width * ?) = given_ts
    ceil((given_ts-start_ts) / width)) -1


          tw0   tw1   tw2   tw3    tw4
      0 ──────┬─────┬──────┬──────┬─────┬
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
        this function is responsible for getting the tw limits ,
        later we'll store em in the db
        returns the start ts and end ts of the given timewindow
        :param tw: the tw that we wanna get the start and end of
        """
        start = self.ts_of_first_flow + (self.width * (tw-1))
        end = start + self.width
        return start, end

