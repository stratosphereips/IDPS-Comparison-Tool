from datetime import datetime, timezone
from hashlib import sha1
import community_id
from timestamp_handler import TimestampHandler

class Hash:
    def __init__(self):
        self.community_id = communityid.CommunityID()
        self.time_handler = TimestampHandler()

    def get_aid(self, flow: dict):
        """
        calculates the flow SHA1(cid+ts) aka All-ID of the flow
        because we need the flow ids to be unique to be able to compare them
        """
        community_id = self.get_community_id(flow)
        ts = self.time_handler.remove_milliseconds_decimals(flow['timestamp'])
        cid_and_ts = f"{self.community_id}-{ts}"

        # Convert the input string to bytes (since hashlib works with bytes)
        input_bytes = cid_and_ts.encode('utf-8')

        return sha1(input_bytes).hexdigest()


    def get_community_id(flow: dict):
        """
        calculates the flow community id of the given flow
        """
        cases = {
        'tcp': communityid.FlowTuple.make_tcp,
        'udp': communityid.FlowTuple.make_udp,
        'icmp': communityid.FlowTuple.make_icmp,
        }

        try:
            proto = flow['proto'].lower()

            if 'icmp' in proto:
                tpl = cases['icmp'](flow['saddr'], flow['daddr'], flow['type'], flow['code'])
            else:
                tpl = cases[proto](flow['saddr'], flow['daddr'], flow['sport'], flow['dport'])

            return community_id.calc(tpl)
        except (KeyError, TypeError):
            # proto doesn't have a community_id.FlowTuple  method
            return ''

