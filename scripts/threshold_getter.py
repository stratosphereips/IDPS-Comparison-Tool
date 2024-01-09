"""
calculates the TP TN FP FN for each threshold in the range 0..150
this script tries all thresholds on all expirements on all tws
"""

from typing import Dict
from pprint import pp
from scripts.extracted_levels import extracted_threat_levels


metrics = {}
for threshold in range(0, 150):
    metrics[threshold] = {}

    for exp, scores in extracted_threat_levels.items():
        exp: str
        scores: Dict[str, float]

        # the dir name aka exp name has the label in it
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






