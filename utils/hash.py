import aid_hash

from .timestamp_handler import TimestampHandler

class Hash:
    def __init__(self):
        self.aid = aid_hash.AID()
        self.time_handler = TimestampHandler()


    def get_aid(self, flow: dict):
        """
        calculates the  AID hash of the flow aka All-ID of the flow
        """
        # aid_hash lib only accepts unix ts
        ts: str = flow['timestamp']
        ts: str = self.time_handler.assert_microseconds(ts)

        cases = {
            'tcp': aid_hash.FlowTuple.make_tcp,
            'udp': aid_hash.FlowTuple.make_udp,
            'icmp': aid_hash.FlowTuple.make_icmp,
        }

        try:
            proto = flow['proto'].lower()

            if 'icmp' in proto:
                tpl = cases['icmp'](ts,
                                    flow['saddr'],
                                    flow['daddr'],
                                    flow['type'],
                                    flow['code'])
            else:
                tpl = cases[proto](ts,
                                   flow['saddr'],
                                   flow['daddr'],
                                   flow['sport'],
                                   flow['dport'])

            return self.aid.calc(tpl)
        except (KeyError, TypeError):
            # proto doesn't have an aid.FlowTuple  method
            return ''




