"""Prepare the compact feature subset from the verified Zenodo AWID3 archive.

The source archive contains a pickle. This script checks the published MD5 before
unpickling. Only use the archive from the cited Zenodo record.
"""
from __future__ import annotations
import argparse, csv, hashlib, pickle, zipfile
from pathlib import Path
import numpy as np

EXPECTED_MD5='0b29e1afa48100e65003da3df3780eb1'
MEMBER_SUFFIX='/data_blocks_w_100_rows/100_1_attack.pkl'

def extract(archive: Path, output: Path):
    digest=hashlib.md5(archive.read_bytes()).hexdigest()
    if digest != EXPECTED_MD5:
        raise SystemExit(f'Archive MD5 mismatch: expected {EXPECTED_MD5}, got {digest}')
    with zipfile.ZipFile(archive) as z:
        matches=[n for n in z.namelist() if n.endswith(MEMBER_SUFFIX)]
        if len(matches)!=1: raise SystemExit(f'Expected one {MEMBER_SUFFIX} member, found {len(matches)}')
        with z.open(matches[0]) as f: windows=pickle.load(f)
    a=np.asarray(windows,dtype=np.float64)
    if a.ndim!=3 or a.shape[1:]!=(100,17):
        raise SystemExit(f'Unexpected AWID3 array shape: {a.shape}')
    labels=a[:,:,16]
    if not np.all(labels==labels[:,0,None]):
        raise SystemExit('Labels vary within a 100-frame window.')
    rows=[]
    for i,w in enumerate(a):
        raw=w[:,:16]
        subtype=np.rint(raw[:,9]*14).astype(int)
        frame_type=np.rint(raw[:,8]*2).astype(int)
        deauth=(subtype==12)
        burst=int(np.convolve(deauth.astype(int),np.ones(10,dtype=int),mode='valid').max())
        _,subtype_counts=np.unique(subtype,return_counts=True)
        type_counts=np.bincount(np.clip(frame_type,0,2),minlength=3)
        p=type_counts[type_counts>0]/100
        entropy=float(-(p*np.log2(p)).sum())
        rows.append({
          'window_id':i,'label':int(labels[i,0]>0),
          'frame_length_mean_normalized':float(raw[:,0].mean()),
          'rssi_mean_normalized':float(raw[:,2].mean()),
          'rssi_std_normalized':float(raw[:,2].std()),
          'management_frame_fraction':float(np.mean(frame_type==0)),
          'deauth_frames_per_100':int(deauth.sum()),
          'max_deauth_in_10_frames':burst,
          'retry_frame_fraction':float(np.mean(raw[:,12]>=0.5)),
          'protected_frame_fraction':float(np.mean(raw[:,15]>=0.5)),
          'unique_subtypes':int(len(subtype_counts)),
          'frame_type_entropy_bits':entropy})
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('w',newline='',encoding='utf-8') as f:
        wr=csv.DictWriter(f,fieldnames=list(rows[0])); wr.writeheader(); wr.writerows(rows)
    print(f'Wrote {len(rows)} windows to {output}; classes: {np.unique(labels[:,0],return_counts=True)}')

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--archive',type=Path,required=True,help='verified Zenodo AWID3 preprocessed ZIP')
    ap.add_argument('--output',type=Path,default=Path(__file__).resolve().parent/'awid3_deauth_windows.csv')
    args=ap.parse_args(); extract(args.archive,args.output)

