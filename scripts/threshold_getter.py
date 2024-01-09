"""
calculates the TP TN FP FN for each threshold in the range 0..150
this script tries all thresholds on all expirements on all tws
"""

from typing import Dict
from pprint import pp
from scripts.extracted_levels import extracted_threat_levels

expirements_number = len(extracted_threat_levels)
metrics = {}
for threshold in range(0, 150):
    metrics[threshold] = {}

    for exp, scores in extracted_threat_levels.items():
        exp: str
        scores: Dict[str, float]

        # the dir name aka exp name has the label in it
        malicious = True
        if 'normal' in exp.lower():
            malicious = False

        tp = 0
        tn = 0
        fp = 0
        fn = 0

        for twid, max_threat_level in scores.items():
            twid: str
            max_threat_level: float

            if malicious:
                # TODO here we are assuming that all tws are malicious
                # so, no FP or TN
                if max_threat_level >= threshold:
                    tp += 1
                elif max_threat_level < threshold:
                    fn += 1
            else:
                # TODO here we are assuming that all tws are benign
                # so, no TP or FN
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


        if tn > max_tn or max_tn==0:
            max_tn = tn
            threshold_with_max_tn = threshold

        if tp > max_tp or max_tp==0:
            max_tp = tp
            threshold_with_max_tp = threshold

        if fp < min_fp or min_fp == float('inf'):
            min_fp = fp
            threshold_with_min_fp = threshold

        if fn < min_fn or min_fn == float('inf'):
            min_fn = fn
            threshold_with_min_fn = threshold

        metrics[threshold].update({exp: confusion_matrix})


print(f"Total experiments: {expirements_number}")

print(f"Threshold with min FN: {threshold_with_min_fn}. min FN: {min_fn}")
print(f"Threshold with min FP: {threshold_with_min_fp}. min FP: {min_fp}")
print(f"Threshold with max TP: {threshold_with_max_tp}. max TP: {max_tp}")
print(f"Threshold with max TN: {threshold_with_max_tn} max TN: {max_tn}")




