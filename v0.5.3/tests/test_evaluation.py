import unittest
from ransomguard.evaluation import evaluate

def case(n,label,score,**kw):
    return dict(case_id=str(n),group_id=str(n),label=label,score=score,split='holdout',
                source='representative_labelled',model='fixed-test-model',request_id='request-'+str(n))|kw

class EvaluationTests(unittest.TestCase):
    def test_review_is_neither_release_nor_detected(self):
        rows=[case(1,'benign',.1),case(2,'benign',.9),case(3,'malicious',.1),case(4,'malicious',.5),case(5,'malicious',.9)]
        report=evaluate(rows)
        self.assertEqual(report['false_positive_rate'],.5)
        self.assertEqual(report['malicious_released_rate'],1/3)
        self.assertEqual(report['review_rate'],.2)
        self.assertFalse(report['calibration_approved']);self.assertFalse(report['policy_changed'])

    def test_mock_and_single_class_never_certify(self):
        result=evaluate([case(1,'benign',0,source='harmless_vm_scenario')])
        self.assertIn('both_classes_required',result['remaining_requirements'])
        self.assertIn('representative_independent_labels_missing',result['remaining_requirements'])
        self.assertIsNone(result['malicious_released_rate'])

    def test_duplicate_leakage_invalid_score_and_model_mix_rejected(self):
        cases=[
          [case(1,'benign',.1),case(1,'benign',.1)],
          [case(1,'benign',.1),case(2,'malicious',.9,request_id='request-1')],
          [case(1,'benign',.1,group_id='same',split='development'),case(2,'malicious',.9,group_id='same')],
          [case(1,'benign',float('nan'))], [case(1,'benign',True)],
          [case(1,'benign',.1),case(2,'malicious',.9,model='different')]]
        for rows in cases:
            with self.subTest(rows=rows),self.assertRaises(ValueError):evaluate(rows)

    def test_development_scores_not_counted_as_holdout(self):
        value=evaluate([case(1,'benign',.95,split='development'),case(2,'benign',.1)])
        self.assertEqual(value['holdout_samples'],1);self.assertEqual(value['false_positive_rate'],0)
