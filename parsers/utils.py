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