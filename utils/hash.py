from datetime import datetime, timezone
from hashlib import sha1
from base64 import b64encode
import communityid

from .timestamp_handler import TimestampHandler

class Hash:
    def __init__(self):
        self.community_id = communityid.CommunityID()
        self.time_handler = TimestampHandler()


    def get_aid(self, flow: dict):
        """
        calculates the flow SHA1(cid+ts) aka All-ID of the flow
        because we need the flow ids to be unique to be able to compare them
        """
        #TODO document this
        community_id = self.get_community_id(flow)
        ts: str = self.time_handler.remove_milliseconds_decimals(flow['timestamp'])

        aid = f"{community_id}-{ts}"

        # convert the input string to bytes (since hashlib works with bytes)
        aid: str = sha1(aid.encode('utf-8')).hexdigest()

        return str(b64encode(aid.encode('utf-8')))


    def get_community_id(self, flow: dict):
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

            return self.community_id.calc(tpl)
        except (KeyError, TypeError):
            # proto doesn't have a community_id.FlowTuple  method
            return ''

