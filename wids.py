"""AWID3-trained, passive wireless intrusion detection prototype.

Modes: train/evaluate, safe offline replay, and optional receive-only Scapy capture.
No packet injection, deauthentication, or blocking is implemented.
"""
from __future__ import annotations
import argparse, csv, json, time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score,
                             precision_recall_curve)

ROOT=Path(__file__).resolve().parent
DATA=ROOT/'awid3_deauth_windows.csv'
MODEL=ROOT/'wids_model.joblib'
METRICS=ROOT/'metrics.json'
ALERTS=ROOT/'alerts.jsonl'
FEATURES=[
 'frame_length_mean_normalized','rssi_mean_normalized','rssi_std_normalized',
 'management_frame_fraction','deauth_frames_per_100','max_deauth_in_10_frames',
 'retry_frame_fraction','protected_frame_fraction','unique_subtypes',
 'frame_type_entropy_bits'
]
SEED=42
WINDOW=100
STRIDE=50

def load_data(path=DATA):
    with Path(path).open(newline='',encoding='utf-8-sig') as f:
        rows=list(csv.DictReader(f))
    if len(rows)<30: raise SystemExit('Need at least 30 prepared AWID3 windows.')
    missing=[c for c in FEATURES+['label','window_id'] if c not in rows[0]]
    if missing: raise SystemExit(f'Missing CSV columns: {missing}')
    rows.sort(key=lambda r:int(r['window_id']))
    x=np.asarray([[float(r[k]) for k in FEATURES] for r in rows],dtype=float)
    y=np.asarray([int(r['label']) for r in rows],dtype=int)
    if not np.isin(y,[0,1]).all(): raise SystemExit('Labels must be 0=normal or 1=deauthentication.')
    return rows,x,y

def new_forest():
    # Carries forward the imbalance-aware Random Forest approach from the
    # user's insider-threat project, with a threshold tuned on a validation tail.
    return RandomForestClassifier(n_estimators=300,max_features='sqrt',min_samples_leaf=2,
       class_weight='balanced_subsample',random_state=SEED,n_jobs=-1)

def positive_probability(model,x):
    return model.predict_proba(x)[:,list(model.classes_).index(1)]

def tune_threshold(y_true,prob):
    p,r,t=precision_recall_curve(y_true,prob)
    if len(t)==0: return .5
    f=2*p[:-1]*r[:-1]/np.maximum(p[:-1]+r[:-1],1e-12)
    return float(t[int(np.nanargmax(f))])

def append_alert(alert):
    ALERTS.parent.mkdir(parents=True,exist_ok=True)
    with ALERTS.open('a',encoding='utf-8') as f: f.write(json.dumps(alert)+'\n')

def train(data_path=DATA):
    rows,x,y=load_data(data_path); n=len(rows)
    # The published file stores all normal-only blocks followed by all
    # deauthentication blocks. Split each contiguous class run chronologically
    # so every segment has both labels. Leave two-window gaps because adjacent
    # source windows overlap by 50 of their 100 frames.
    fit_parts=[]; val_parts=[]; final_parts=[]; test_parts=[]
    starts=np.r_[0,np.where(y[1:]!=y[:-1])[0]+1,n]
    for lo,hi in zip(starts[:-1],starts[1:]):
        run=np.arange(lo,hi); m=len(run)
        cut64=int(.64*m); cut80=int(.80*m)
        fit_parts.append(run[:cut64])
        val_parts.append(run[cut64+1:max(cut64+1,cut80-1)])
        final_parts.append(run[:max(0,cut80-1)])
        test_parts.append(run[min(m,cut80+1):])
    fit_idx=np.concatenate(fit_parts); val_idx=np.concatenate(val_parts)
    final_idx=np.concatenate(final_parts); test_idx=np.concatenate(test_parts)
    if min(len(np.unique(y[a])) for a in (fit_idx,val_idx,final_idx,test_idx))<2:
        raise SystemExit('Chronological class-run split did not retain both classes.')
    provisional=new_forest().fit(x[fit_idx],y[fit_idx])
    threshold=tune_threshold(y[val_idx],positive_probability(provisional,x[val_idx]))
    model=new_forest().fit(x[final_idx],y[final_idx])
    prob=positive_probability(model,x[test_idx]); pred=(prob>=threshold).astype(int)
    cm=confusion_matrix(y[test_idx],pred,labels=[0,1])
    report=classification_report(y[test_idx],pred,labels=[0,1],target_names=['normal','deauthentication'],output_dict=True,zero_division=0)
    metrics={
      'dataset':'AWID3 preprocessed 100-row deauthentication class blocks',
      'dataset_record':'https://zenodo.org/records/17406710',
      'source_file':'data_blocks_w_100_rows/100_1_attack.pkl',
      'source_archive_md5':'0b29e1afa48100e65003da3df3780eb1',
      'rows_total':n,'class_counts':{'normal':int((y==0).sum()),'deauthentication':int((y==1).sum())},
      'split':'chronological within each contiguous label run; fit 64%, validation 16%, test 20%, with two-window embargoes; windows overlap by 50 frames',
      'fit_windows':len(fit_idx),'validation_windows':len(val_idx),'final_train_windows':len(final_idx),'test_windows':len(test_idx),
      'threshold':threshold,'accuracy':float(accuracy_score(y[test_idx],pred)),
      'precision':float(precision_score(y[test_idx],pred,zero_division=0)),
      'recall':float(recall_score(y[test_idx],pred,zero_division=0)),
      'f1':float(f1_score(y[test_idx],pred,zero_division=0)),
      'confusion_matrix':cm.tolist(),'confusion_matrix_order':['normal','deauthentication'],
      'classification_report':report,
      'test_window_ids':[int(rows[i]['window_id']) for i in test_idx],
      'feature_importance':sorted([{'feature':f,'importance':float(v)} for f,v in zip(FEATURES,model.feature_importances_)],key=lambda v:v['importance'],reverse=True),
      'limitations':'Preprocessed single deauthentication capture, not a multi-site field benchmark. The held-out tail is chronological but from the same source capture. Live RSSI and frame-length scaling require adapter calibration.'
    }
    bundle={'model':model,'features':FEATURES,'threshold':threshold,'window':WINDOW,'stride':STRIDE,
      'capture_scales':{'max_frame_bytes':2346,'rssi_min_dbm':-100,'rssi_max_dbm':-20},
      'dataset_record':metrics['dataset_record']}
    joblib.dump(bundle,MODEL)
    METRICS.write_text(json.dumps(metrics,indent=2),encoding='utf-8')
    print('AWID3 chronological held-out test')
    print(f"Windows: fit {len(fit_idx)}, validation {len(val_idx)}, final train {len(final_idx)}, test {len(test_idx)}")
    print(f"Validation-tuned threshold: {threshold:.3f}")
    print(f"Accuracy {metrics['accuracy']:.3f} | Precision {metrics['precision']:.3f} | Recall {metrics['recall']:.3f} | F1 {metrics['f1']:.3f}")
    print('Confusion matrix (actual rows, predicted columns; normal, deauthentication):')
    print(cm)
    print('Top features:',', '.join(v['feature'] for v in metrics['feature_importance'][:5]))
    print(f'Saved {MODEL.name} and {METRICS.name}')

def score_vector(bundle,values):
    x=np.asarray([[values[f] for f in bundle['features']]],dtype=float)
    prob=float(positive_probability(bundle['model'],x)[0])
    return prob,prob>=float(bundle['threshold'])

def replay(data_path=DATA,limit=2):
    bundle=joblib.load(MODEL); rows,x,y=load_data(data_path)
    metrics=json.loads(METRICS.read_text(encoding='utf-8'))
    test=set(metrics['test_window_ids'])
    candidates=[i for i,r in enumerate(rows) if int(r['window_id']) in test]
    probs=positive_probability(bundle['model'],x[candidates])
    labels=y[candidates]
    normal=[(i,p) for i,p in zip(candidates,probs) if y[i]==0]
    attacks=[(i,p) for i,p in zip(candidates,probs) if y[i]==1]
    selected=[]
    if normal: selected.append(min(normal,key=lambda z:z[1]))
    if attacks: selected.append(max(attacks,key=lambda z:z[1]))
    print('Safe offline replay of held-out AWID3 windows (no radio transmission)')
    for i,p in selected[:limit]:
        alert=p>=bundle['threshold']
        label='DEAUTH FLOOD' if alert else 'normal'
        print(f"window {rows[i]['window_id']}: dataset label={'deauthentication' if y[i] else 'normal'}, model={label}, P(attack)={p:.3f}, deauth_frames/100={int(float(rows[i]['deauth_frames_per_100']))}")
        if alert:
            event={'timestamp_utc':datetime.now(timezone.utc).isoformat(),'kind':'WIDS_ALERT',
              'source':'AWID3 offline replay','window_id':int(rows[i]['window_id']),
              'predicted':'deauthentication','probability':p,
              'threshold':float(bundle['threshold']),
              'deauth_frames_per_100':int(float(rows[i]['deauth_frames_per_100'])),
              'action':'logged only; passive WIDS'}
            append_alert(event); print('ALERT logged to alerts.jsonl')

def raw_packet_values(pkt,rssi_min=-100.,rssi_max=-20.,max_frame_bytes=2346.):
    from scapy.layers.dot11 import Dot11, RadioTap
    dot=pkt.getlayer(Dot11)
    if dot is None: return None
    try: dbm=float(pkt.getlayer(RadioTap).dBm_AntSignal)
    except (AttributeError,TypeError,ValueError): dbm=rssi_min
    rssi=float(np.clip((dbm-rssi_min)/(rssi_max-rssi_min),0,1))
    fc=int(dot.FCfield)
    return {'length':float(np.clip(len(pkt)/max_frame_bytes,0,1)),
      'rssi':rssi,'type':int(dot.type),'subtype':int(dot.subtype),
      'retry':bool(fc&8),'protected':bool(fc&64),
      'source':str(dot.addr2 or 'unknown')}

def summarize_raw_window(frames):
    lens=np.asarray([f['length'] for f in frames],float)
    rssis=np.asarray([f['rssi'] for f in frames],float)
    sub=np.asarray([f['subtype'] for f in frames],int)
    typ=np.asarray([f['type'] for f in frames],int)
    deauth=(sub==12)
    burst=int(max(np.convolve(deauth.astype(int),np.ones(10,dtype=int),mode='valid')))
    counts=np.bincount(np.clip(typ,0,2),minlength=3); p=counts[counts>0]/len(frames)
    return {'frame_length_mean_normalized':float(lens.mean()),
      'rssi_mean_normalized':float(rssis.mean()),'rssi_std_normalized':float(rssis.std()),
      'management_frame_fraction':float(np.mean(typ==0)),
      'deauth_frames_per_100':int(deauth.sum()),'max_deauth_in_10_frames':burst,
      'retry_frame_fraction':float(np.mean([f['retry'] for f in frames])),
      'protected_frame_fraction':float(np.mean([f['protected'] for f in frames])),
      'unique_subtypes':int(len(np.unique(sub))),
      'frame_type_entropy_bits':float(-(p*np.log2(p)).sum())}

def capture(interface,seconds,rssi_min=-100.,rssi_max=-20.,max_frame_bytes=2346.):
    try:
        from scapy.all import sniff
    except ImportError: raise SystemExit('Install scapy with: python -m pip install scapy')
    bundle=joblib.load(MODEL); frames=[]; new_count=0
    scales=bundle['capture_scales']
    rssi_min=float(rssi_min); rssi_max=float(rssi_max); max_frame_bytes=float(max_frame_bytes)
    if rssi_max<=rssi_min or max_frame_bytes<=0: raise SystemExit('Invalid capture normalization range.')
    print(f'Listen-only capture on {interface} for {seconds}s. Use only an authorized monitor-mode adapter/network.')
    def on_packet(pkt):
        nonlocal frames,new_count
        item=raw_packet_values(pkt,rssi_min,rssi_max,max_frame_bytes)
        if item is None: return
        frames.append(item); new_count+=1
        if len(frames)>=WINDOW and (len(frames)==WINDOW or new_count>=STRIDE):
            window=frames[-WINDOW:]; new_count=0
            values=summarize_raw_window(window)
            prob,alert=score_vector(bundle,values)
            deauth_sources=Counter(f['source'] for f in window if f['subtype']==12)
            if alert:
                event={'timestamp_utc':datetime.now(timezone.utc).isoformat(),'kind':'WIDS_ALERT',
                  'source':'passive monitor capture','interface':interface,
                  'offending_macs':deauth_sources.most_common(5),'probability':prob,
                  'threshold':float(bundle['threshold']),'features':values,
                  'action':'logged only; passive WIDS'}
                append_alert(event)
                print(f"ALERT deauthentication activity P={prob:.3f}; source(s)={deauth_sources.most_common(3)}")
            else:
                print(f"window={len(frames)} P(attack)={prob:.3f} normal")
    sniff(iface=interface,timeout=seconds,prn=on_packet,store=False)
    print(f'Capture finished. Parsed {len(frames)} 802.11 frames; alerts appended to {ALERTS.name}.')

def main():
    ap=argparse.ArgumentParser(description='Passive AWID3-trained Wi-Fi deauthentication WIDS')
    sub=ap.add_subparsers(dest='command',required=True)
    p=sub.add_parser('train',help='train and report metrics from the included AWID3 feature windows')
    p.add_argument('--data',default=str(DATA))
    p=sub.add_parser('replay',help='safely replay held-out AWID3 windows offline')
    p.add_argument('--data',default=str(DATA))
    p=sub.add_parser('capture',help='passively score traffic from an authorized monitor-mode interface')
    p.add_argument('--interface',required=True); p.add_argument('--seconds',type=int,default=60)
    p.add_argument('--rssi-min',type=float,default=-100); p.add_argument('--rssi-max',type=float,default=-20)
    p.add_argument('--max-frame-bytes',type=float,default=2346)
    args=ap.parse_args()
    if args.command=='train': train(args.data)
    elif args.command=='replay': replay(args.data)
    else: capture(args.interface,args.seconds,args.rssi_min,args.rssi_max,args.max_frame_bytes)

if __name__=='__main__': main()

