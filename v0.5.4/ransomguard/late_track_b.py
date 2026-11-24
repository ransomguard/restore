"""One fresh-evidence reassessment of an ambiguous B incident, without waiting in intake."""
import copy
import json
import time

REASON = 'jev_ambiguous_demo_threshold'

def promote(db, owner, incident_id, incoming):
    row = db.execute('SELECT track,state,reason,payload FROM response_jobs WHERE id=? AND owner=?', (incident_id,owner)).fetchone()
    if not row or row[:3] != ('B','REVIEW_REQUIRED',REASON) or incoming.get('track')!='B':return False
    previous=json.loads(row[3]);old=previous.get('evidence',{})
    if previous.get('resume_b_review') or incoming['pid']!=previous['pid'] or incoming['generation']!=previous['generation']:return False
    if db.execute('SELECT 1 FROM track_b_reassessment_history WHERE incident_id=?',(incident_id,)).fetchone():return False
    # A fresh kernel fact gets a fresh short action deadline; the incident itself
    # is bounded to three minutes, and its original recovery cutoff is retained.
    if not (previous['filetime'] < incoming['filetime'] <= previous['filetime']+180*10_000_000 and time.time()<=incoming['deadline']):return False
    paths=old.get('evidence',{}).get('sample_source_paths',[])
    fresh=incoming.get('evidence',{}).get('evidence',{}).get('sample_source_paths',[])
    if not set(fresh)-set(paths):return False
    effects=old.get('verified_write_effects',{})
    if effects.get('files_unverified')!=0 or effects.get('bounded_scan_incomplete') or not effects.get('changed_relative_paths'):return False
    job=copy.deepcopy(incoming);job['id']=incident_id
    job['resume_b_review']=True;job['previous_review_reason']=REASON
    job['recovery_filetime']=previous.get('recovery_filetime',previous['filetime'])
    job['prior_changed_paths']=effects['changed_relative_paths']
    union=list(dict.fromkeys(paths+fresh))
    if len(union)>32:return False
    job['evidence']['evidence']['sample_source_paths']=union
    job['evidence']['reassessment_context']={'reason':'new_observed_paths_after_ambiguous_review','prior_changed_files':len(effects['changed_relative_paths']),'counts_are_current_window_only':True}
    encoded=json.dumps(job,ensure_ascii=False,allow_nan=False)
    if len(encoded.encode('utf8'))>60_000:return False
    db.execute("UPDATE response_jobs SET state='READY',reason=NULL,payload=? WHERE id=?",(encoded,incident_id))
    return True

def new_verified_facts(job):
    effects=job.get('evidence',{}).get('verified_write_effects',{})
    before=set(job.get('prior_changed_paths',[]));after=set(effects.get('changed_relative_paths',[]))
    return bool(before and before.issubset(after) and after-before and effects.get('files_unverified')==0 and not effects.get('bounded_scan_incomplete'))
