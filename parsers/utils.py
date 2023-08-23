from datetime import datetime, timezone
import communityid

def get_community_id(flow: dict):
    """
    calculates the flow community id based on the protocol
    """
    community_id = communityid.CommunityID()
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


def convert_iso_8601_to_unix_timestamp(ts: str) -> float:
    """
    converts iso 8601 format to unix timestamp
    expected format: %Y-%m-%dT%H:%M:%S.%f%z
    :param ts: ts in expected format
    :return: the given ts in unix format
    """
    dt = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')

    # convert datetime to time-aware timezone at UTC
    # so correct timestamp is returned
    dt = dt.replace(tzinfo=timezone.utc)

    # Return the time in seconds since the epoch
    seconds_since_epoch = dt.timestamp()

    return seconds_since_epoch
