"""Train RansomShield's TCN + XGBoost hybrid on safe synthetic sequences."""
import argparse, json
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
import xgboost as xgb

FEATURE_NAMES = ["created_count", "modified_count", "deleted_count", "cpu_percent", "memory_percent", "process_count", "canary_accessed", "canary_modified", "decoy_files_touched", "directories_touched", "operation_rate"]
SEQUENCE_LENGTH, TCN_FILTERS, KERNEL_SIZE, DILATION = 8, 8, 3, 2

def make_dataset(size, seed):
    rng = np.random.default_rng(seed); sequences, labels = [], []
    for _ in range(size):
        suspicious = rng.random() < .42; onset = int(rng.integers(1, 5)) if suspicious else 9
        intensity = float(rng.uniform(.75, 1.25)); sequence = []
        for step in range(SEQUENCE_LENGTH):
            active = suspicious and step >= onset; ramp = intensity * (.45 + .18 * (step-onset)) if active else 0
            if active:
                created=max(0,int(rng.normal(13*ramp,4))); modified=max(0,int(rng.normal(21*ramp,6))); deleted=max(0,int(rng.normal(8*ramp,3)))
                cpu=np.clip(rng.normal(55+25*ramp,10),0,100); memory=np.clip(rng.normal(60+15*ramp,9),0,100); processes=max(20,int(rng.normal(165,45)))
                ca=int(rng.random()<min(.35+.12*ramp,.9)); cm=int(ca and rng.random()<.75); touched=created+modified+deleted; dirs=int(np.clip(rng.normal(2.5+ramp,.8),1,5))
            else:
                created=max(0,int(rng.normal(2,2))); modified=max(0,int(rng.normal(3,2.5))); deleted=max(0,int(rng.normal(.5,.8)))
                cpu=np.clip(rng.normal(28,16),0,100); memory=np.clip(rng.normal(52,13),0,100); processes=max(20,int(rng.normal(125,35)))
                ca=int(rng.random()<.012); cm=int(ca and rng.random()<.08); touched=created+modified+deleted; dirs=int(np.clip(rng.normal(.7,.7),0,3))
            sequence.append([created,modified,deleted,cpu,memory,processes,ca,cm,touched,dirs,touched/2])
        label=int(suspicious); label = 1-label if rng.random()<.035 else label
        sequences.append(sequence); labels.append(label)
    order=rng.permutation(size)
    return np.asarray(sequences,dtype=np.float32)[order],np.asarray(labels)[order]

def causal_windows(values):
    indices=np.maximum(np.arange(SEQUENCE_LENGTH)[:,None]-np.arange(KERNEL_SIZE)[None,:]*DILATION,0)
    return values[:,indices,:]

def train_tcn(values, labels, seed, epochs=180, lr=.035):
    rng=np.random.default_rng(seed); kernels=rng.normal(0,.08,(TCN_FILTERS,KERNEL_SIZE,len(FEATURE_NAMES))); bias=np.zeros(TCN_FILTERS); head=rng.normal(0,.08,TCN_FILTERS); hb=0.; windows=causal_windows(values); y=labels.astype(float)
    for _ in range(epochs):
        pre=np.einsum("ntkc,fkc->ntf",windows,kernels)+bias; act=np.maximum(pre,0); emb=act.mean(1); logits=np.clip(emb@head+hb,-30,30); error=(1/(1+np.exp(-logits))-y)/len(y)
        gh=emb.T@error+1e-4*head; ghb=error.sum(); gp=(error[:,None]*head[None,:])[:,None,:]/SEQUENCE_LENGTH*(pre>0)
        gk=np.einsum("ntf,ntkc->fkc",gp,windows)+1e-4*kernels; gb=gp.sum((0,1))
        kernels-=lr*np.clip(gk,-2,2); bias-=lr*np.clip(gb,-2,2); head-=lr*np.clip(gh,-2,2); hb-=lr*ghb
    return kernels.astype(np.float32),bias.astype(np.float32)

def embedding(values,kernels,bias):
    return np.maximum(np.einsum("ntkc,fkc->ntf",causal_windows(values),kernels)+bias,0).mean(1)

def metric(labels,prob):
    p=prob>=.6; tp=np.sum(p&(labels==1)); fp=np.sum(p&(labels==0)); tn=np.sum(~p&(labels==0)); fn=np.sum(~p&(labels==1)); precision=tp/max(tp+fp,1); recall=tp/max(tp+fn,1)
    return {k:round(float(v),4) for k,v in {"accuracy":(tp+tn)/len(labels),"precision":precision,"recall":recall,"f1":2*precision*recall/max(precision+recall,1e-9),"false_positive_rate":fp/max(fp+tn,1)}.items()}

def fit(features,labels,seed):
    params={"max_depth":4,"eta":.05,"subsample":.9,"colsample_bytree":.9,"objective":"binary:logistic","eval_metric":"logloss","seed":seed,"nthread":1}
    return xgb.train(params,xgb.DMatrix(features,label=labels),num_boost_round=160)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--samples",type=int,default=6000); parser.add_argument("--seed",type=int,default=20260827); parser.add_argument("--output-dir",type=Path,default=Path("app/artifacts")); args=parser.parse_args()
    if args.samples<200: parser.error("--samples must be at least 200")
    x,y=make_dataset(args.samples,args.seed); split=int(args.samples*.8); train_x,test_x=x[:split],x[split:]; train_y,test_y=y[:split],y[split:]
    flat=train_x.reshape(-1,len(FEATURE_NAMES)); means=flat.mean(0); scales=np.maximum(flat.std(0),1e-6); train_z=(train_x-means)/scales; test_z=(test_x-means)/scales
    kernels,bias=train_tcn(train_z,train_y,args.seed); train_e=embedding(train_z,kernels,bias); test_e=embedding(test_z,kernels,bias)
    baseline=fit(train_z[:,-1,:],train_y,args.seed); baseline_metrics=metric(test_y,baseline.predict(xgb.DMatrix(test_z[:,-1,:])))
    hybrid=fit(np.concatenate([train_z[:,-1,:],train_e],1),train_y,args.seed); hybrid_metrics=metric(test_y,hybrid.predict(xgb.DMatrix(np.concatenate([test_z[:,-1,:],test_e],1))))
    args.output_dir.mkdir(parents=True,exist_ok=True); hybrid.save_model(args.output_dir/"xgboost_model.json"); np.savez(args.output_dir/"tcn_weights.npz",kernels=kernels,bias=bias)
    artifact={"schema_version":2,"model_type":"tcn_xgboost_hybrid","display_name":"TCN + XGBoost Behavioral Model","feature_names":FEATURE_NAMES,"sequence_length":SEQUENCE_LENGTH,"kernel_size":KERNEL_SIZE,"dilation":DILATION,"tcn_filters":TCN_FILTERS,"means":means.tolist(),"scales":scales.tolist(),"tcn_artifact":"tcn_weights.npz","xgboost_artifact":"xgboost_model.json","decision_threshold":.6,"trained_at":datetime.now(timezone.utc).isoformat(),"training":{"source":"safe_synthetic_sequential_decoy_telemetry","seed":args.seed,"training_samples":split,"test_samples":args.samples-split,"xgboost_only_metrics":baseline_metrics},"metrics":hybrid_metrics}
    (args.output_dir/"behavioral_model.json").write_text(json.dumps(artifact,indent=2)+"\n",encoding="utf-8"); print(json.dumps({"xgboost_only_metrics":baseline_metrics,"hybrid_metrics":hybrid_metrics},indent=2))
if __name__=="__main__": main()
