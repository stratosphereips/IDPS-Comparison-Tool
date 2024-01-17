"""
calculates the TP TN FP FN for each threshold in the range 0..150
this script tries all thresholds on all expirements on all tws
"""

from typing import Dict
from pprint import pp
from scripts.extracted_levels import extracted_threat_levels
from scripts.extracted_gt_tw_labels import gt_tw_labels


def is_tw_malicious(experiment: str, timewindow: int) -> bool:
    """
    checks whether the ground truth label of the given timewindow is malicious
    :param experiment: name of experiment to check
    :param timewindow: number of tw to check
    """
    try:
        return gt_tw_labels[experiment][timewindow] == 'malicious'
    except:
        # If a timewindow was detected by one of the tools, and not detected
        # by the ground truth, for example negative timewindows in slips,
        # we consider the gt label of it as "benign"
        # return False
        print(f"problem getting the label of {experiment} {timewindow}")


def metrics_sum(metrics: dict):
    """
    prints the sum of all tp fp tn fn for all thresholds
    """
    max_tn = 0
    max_tp = 0
    min_fp = float("inf")
    min_fn = float("inf")


    for threshold, expirements in metrics.items():
        threshold: int
        expirements: dict

        tot_fp = 0
        tot_fn = 0
        tot_tp = 0
        tot_tn = 0

        for exp_name, conf_matrix in expirements.items():
            exp_name: str
            conf_matrix: dict
            tot_fp += conf_matrix['FP']
            tot_fn += conf_matrix['FN']
            tot_tp += conf_matrix['TP']
            tot_tn += conf_matrix['TN']

        print(f"Threshold: {threshold}:"
              f"\n total FPs: {tot_fp}"
              f"\n total FNs: {tot_fn}"
              f"\n total TPs: {tot_tp}"
              f"\n total TNs: {tot_tn}"
              )

        if tot_tn > max_tn or max_tn==0:
            max_tn = tot_tn
            threshold_with_max_tn = threshold

        if tot_tp > max_tp or max_tp==0:
            max_tp = tot_tp
            threshold_with_max_tp = threshold

        if tot_fp < min_fp or min_fp == float('inf'):
            min_fp = tot_fp
            threshold_with_min_fp = threshold

        if tot_fn < min_fn or min_fn == float('inf'):
            min_fn = tot_fn
            threshold_with_min_fn = threshold




    print(f"Threshold with min FN: {threshold_with_min_fn}. min FN: {min_fn}")
    print(f"Threshold with min FP: {threshold_with_min_fp}. min FP: {min_fp}")
    print(f"Threshold with max TP: {threshold_with_max_tp}. max TP: {max_tp}")
    print(f"Threshold with max TN: {threshold_with_max_tn} max TN: {max_tn}")



expirements_number = len(extracted_threat_levels)

metrics = {}
for threshold in range(1, 150):
    metrics[threshold] = {}

    for exp, scores in extracted_threat_levels.items():
        exp: str
        scores: Dict[str, float]

        tp = 0
        tn = 0
        fp = 0
        fn = 0

        for twid, max_threat_level in scores.items():
            twid: str
            max_threat_level: float
            # get the gt label of this twid
            malicious: bool = is_tw_malicious(exp, int(twid))

            if malicious:
                if max_threat_level >= threshold:
                    tp += 1
                elif max_threat_level < threshold:
                    fn += 1
            else:
                if max_threat_level >= threshold:
                    fp +=1
                elif max_threat_level < threshold:
                    tn += 1

        confusion_matrix = {
            'TP': tp,
            'FP': fp,
            'TN': tn,
            'FN': fn
        }
        metrics[threshold].update({exp: confusion_matrix})

print(f"Total experiments: {expirements_number}")

pp(metrics)
metrics_sum(metrics)



