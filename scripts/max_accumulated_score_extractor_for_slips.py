"""
This script extracts the highest accumulated threat level of each time
window in the given alerts.json. it only prints timewindows of the
 given host ip

Usage:
python3 max_accumulated_score_extractor_for_slips.py <slips' alerts.json> <host ip>

"""

import json
import sys
import ipaddress
from typing import Dict
from pprint import pp

tws = {}
alertsjson = sys.argv[1]
srcip = sys.argv[2]

def count_and_print_duplicate_scores(scores: list):
    """
    prints x -- y times for duplicate continuous scores found in each twid
    """
    ctr = 0
    printed = False
    last_score_in_twid = False

    for i in range(len(scores)):
        score = float(scores[i])

        try:
            prev_score = float(scores[i-1])
        except IndexError:
            # cur score is the first one
            prev_score = float(0)
            last_score_in_twid = False



        try:
            nxt_score = float(scores[i+1])
        except IndexError:
            # cur score is the last one
            nxt_score = 999999999999
            last_score_in_twid = True

        #######################################

        if score != prev_score:
            # reset the zeros ctr

            if (not printed and ctr > 0):
                print(f"{prev_score} --  {ctr} times")
                printed = True
                ctr = 0
            if score != nxt_score:
                print(score)
                # bcus if it was = next score, we'll be counting them
            else:
                ctr = 1
        elif score == prev_score:
            # consequent zeros
            ctr +=1
            printed = False

        if last_score_in_twid:
            print(f"{prev_score} --  {ctr} times")


def print_json_max_accumulated_score(
        sorted_tws: Dict[str, float]
    ):
    """
    prints this dict
    {filename: { 'twid': max_acc_threat_level }}
    """
    res = {alertsjson: {} }
    for timewindow, scores in sorted_tws.items():
        timewindow: int
        scores: list
        res[alertsjson].update({timewindow: max(scores)})

    pp(res)

def print_max_accumulated_score(scores: list):

    print(max(scores))


def get_ip_version(srcip):
    # determine th eversion of the given IP
    try:
        ipaddress.IPv4Address(srcip)
        ip_version = "IP4"
    except ipaddress.AddressValueError:
        ip_version = "IP6"
    return ip_version





ip_version: str = get_ip_version(srcip)

with open(alertsjson, 'r') as f:
    lines_ctr = 0
    while line := f.readline():
        lines_ctr += 1
        line: dict = json.loads(line)
        try:
            sip = line["Source"][0][ip_version][0]
        except Exception as e:
            # detection doesn't match the given ipv4, skip it
            continue

        if sip != srcip:
            continue

        tl = line['accumulated_threat_level']
        twid = line['timewindow']

        if twid not in tws:
            tws.update({twid :  [tl]})
        else:
            tws[twid].append(tl)


#print(f"total alerts.json lines read: {lines_ctr}")

sorted_tws = dict(sorted(tws.items()))


# for twid, scores in sorted_tws.items():
    #print(f"\n\ntimewindow {twid}\n")

    #count_and_print_duplicate_scores(scores)

    #print_max_accumulated_score(scores)
    # pass

print_json_max_accumulated_score(sorted_tws)