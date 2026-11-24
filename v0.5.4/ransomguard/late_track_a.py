"""One bounded evidence upgrade, never a retry of termination or restoration."""
import json
import time

REVIEW_REASONS = frozenset(('jev_ambiguous_demo_threshold', 'jev_query_or_validation_failed',
                          'jev_score_invalid', 'jev_request_identity_invalid', 'jev_client_not_configured'))


def valid_proof(job):
    p = job.get('evidence', {})
    try:
        return (job['track'] == 'A' and p['high_entropy_write'] is True
                and p['pid'] == p['parent_pid'] == p['creator_pid'] == job['pid']
                and p['create_time'] == job['generation']
                and type(p['matched_rule_id']) is int and p['matched_rule_id'] in range(1001, 1009)
                and p['path'] == job['path'] and p['blocked_child_pid'] != job['pid']
                and job['generation'] <= p['write_filetime'] <= p['rule_filetime']
                and 0 <= p['rule_filetime'] - p['write_filetime'] <= 100_000_000
                and job['filetime'] == p['rule_filetime'] and time.time() <= job['deadline'])
    except (KeyError, TypeError):
        return False


def promote(db, owner, incident_id):
    row = db.execute('SELECT track,state,reason,payload FROM response_jobs WHERE id=? AND owner=?',
                     (incident_id, owner)).fetchone()
    upgrade = db.execute("SELECT payload FROM response_track_a_updates WHERE id=? AND owner=? AND state='waiting'",
                         (incident_id, owner)).fetchone()
    if not row or not upgrade or row[0] != 'B':
        return False
    if row[1] != 'READY' and not (row[1] == 'REVIEW_REQUIRED' and row[2] in REVIEW_REASONS):
        return False
    job, previous = json.loads(upgrade[0]), json.loads(row[3])
    if not valid_proof(job):
        return False
    job['id'] = incident_id
    job['deadline'] = min(job['deadline'], previous['deadline'])
    if time.time() > job['deadline']:
        return False
    # Preserve the first incident's recovery cutoff, without weakening proof.
    job['recovery_filetime'] = min(previous['filetime'], job['filetime'])
    job['resume_jev_review'] = row[1] == 'REVIEW_REQUIRED'
    job['previous_review_reason'] = row[2]
    db.execute("UPDATE response_jobs SET track='A',state='READY',reason=NULL,payload=? WHERE id=?",
               (json.dumps(job, ensure_ascii=False), incident_id))
    db.execute("UPDATE response_track_a_updates SET state='promoted' WHERE id=?", (incident_id,))
    return True
