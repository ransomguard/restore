"""Offline evaluation of independently labelled JEV results; changes no policy.

Synthetic/VM scenario data is explicitly diagnostic. A report never promotes
itself to a calibrated release or modifies live thresholds, even with zero
observed errors. Users must supply representative, independently labelled data.
"""
import argparse
import json
import math
from pathlib import Path


def evaluate(records, *, benign=0.2, malicious=0.8):
    if not isinstance(records,list) or not 1 <= len(records) <= 100000:
        raise ValueError('Expected 1..100000 labelled cases')
    if any(type(v) not in (int,float) or not math.isfinite(v) for v in (benign,malicious)) or not 0 <= benign < malicious <= 1:
        raise ValueError('Invalid fixed thresholds')
    matrix={label:{decision:0 for decision in ('benign','review','malicious')} for label in ('benign','malicious')}
    ids,requests,groups,models,origins=set(),set(),{},set(),set()
    for item in records:
        if not isinstance(item,dict):raise ValueError('Evaluation rows must be objects')
        for field in ('case_id','group_id','label','split','source','model','request_id'):
            if not isinstance(item.get(field),str) or not item[field].strip():raise ValueError('Missing evaluation field: '+field)
        if item['case_id'] in ids or item['request_id'] in requests:raise ValueError('Duplicate case/request: repeated evidence cannot inflate sample size')
        ids.add(item['case_id']);requests.add(item['request_id'])
        if item['label'] not in matrix or item['split'] not in ('development','holdout'):
            raise ValueError('Expected independent benign/malicious labels and development/holdout split')
        if item['source'] not in ('representative_labelled','harmless_vm_scenario','synthetic_fixture'):
            raise ValueError('Unknown evidence source')
        if groups.setdefault(item['group_id'],item['split']) != item['split']:
            raise ValueError('Related case group crosses development/holdout boundary')
        score=item.get('score')
        if type(score) not in (int,float) or not math.isfinite(score) or not 0<=score<=1:raise ValueError('Invalid JEV score')
        if item['split']=='holdout':
            decision='benign' if score<=benign else 'malicious' if score>=malicious else 'review'
            matrix[item['label']][decision]+=1
            models.add(item['model']);origins.add(item['source'])
    if len(models)>1:raise ValueError('Evaluate each resolved model separately; do not pool different JEV models')
    negatives=sum(matrix['benign'].values());positives=sum(matrix['malicious'].values())
    totals=negatives+positives
    reasons=[]
    if not negatives or not positives:reasons.append('both_classes_required')
    if origins != {'representative_labelled'}:reasons.append('representative_independent_labels_missing')
    reasons.append('operator_representativeness_and_acceptance_criteria_review_required')
    return dict(schema_version=1, thresholds={'benign':benign,'malicious':malicious}, model=next(iter(models),None),
                holdout_matrix=matrix,holdout_samples=totals,independent_groups=len({r['group_id'] for r in records if r['split']=='holdout'}),
                false_positive_rate=matrix['benign']['malicious']/negatives if negatives else None,
                malicious_released_rate=matrix['malicious']['benign']/positives if positives else None,
                review_rate=(matrix['benign']['review']+matrix['malicious']['review'])/totals if totals else None,
                calibration_approved=False,policy_changed=False,remaining_requirements=reasons,
                note='Observed zero errors is not proof of zero population risk; review is neither a true positive nor a benign release.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--benign',type=float,default=.2);parser.add_argument('--malicious',type=float,default=.8)
    args=parser.parse_args()
    source=Path(args.input)
    if source.stat().st_size>16*1024*1024:raise ValueError('Evaluation input exceeds 16 MiB')
    rows=json.loads(source.read_text(encoding='utf-8-sig'))
    if not isinstance(rows,list) or not 1<=len(rows)<=100000:raise ValueError('Expected 1..100000 labelled cases')
    result=evaluate(rows,benign=args.benign,malicious=args.malicious)
    with Path(args.output).open('x',encoding='utf8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(result))


if __name__=='__main__':main()
