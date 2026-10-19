"""Sequential TCN + XGBoost inference for behavioral activity detection."""
import json
from collections import deque
from pathlib import Path
from typing import Dict, Optional
import numpy as np
import xgboost as xgb

FEATURE_NAMES=("created_count","modified_count","deleted_count","cpu_percent","memory_percent","process_count","canary_accessed","canary_modified","decoy_files_touched","directories_touched","operation_rate")

class BehavioralDetector:
    def __init__(self,model_path:Path)->None:
        self.model_path=model_path; self.model=self.booster=self.kernels=self.bias=None; self.history=deque(); self.load_error=None; self.reload()
    def reload(self)->None:
        try:
            model=json.loads(self.model_path.read_text(encoding="utf-8"))
            if model.get("model_type")!="tcn_xgboost_hybrid": raise ValueError("artifact is not a TCN + XGBoost hybrid")
            if model.get("feature_names")!=list(FEATURE_NAMES): raise ValueError("model features do not match the application")
            weights=np.load(self.model_path.parent/model["tcn_artifact"]); self.kernels=weights["kernels"]; self.bias=weights["bias"]
            self.booster=xgb.Booster(); self.booster.load_model(self.model_path.parent/model["xgboost_artifact"]); self.history=deque(maxlen=int(model["sequence_length"])); self.model=model; self.load_error=None
        except (OSError,ValueError,KeyError,json.JSONDecodeError,xgb.XGBoostError) as exc:
            self.model=self.booster=self.kernels=self.bias=None; self.load_error=str(exc)
    @property
    def is_ready(self)->bool: return self.model is not None
    @property
    def display_name(self)->str: return self.model.get("display_name","TCN + XGBoost") if self.model else "Heuristic fallback"
    def _embedding(self,sequence):
        outputs=[]; dilation=int(self.model["dilation"])
        for step in range(len(sequence)):
            window=np.stack([sequence[max(0,step-tap*dilation)] for tap in range(int(self.model["kernel_size"]))])
            outputs.append(np.maximum(np.einsum("fkc,kc->f",self.kernels,window)+self.bias,0))
        return np.mean(outputs,axis=0)
    def predict_probability(self,features:Dict[str,float])->Optional[float]:
        if not self.model: return None
        row=np.asarray([float(features[name]) for name in FEATURE_NAMES],dtype=np.float32); row=(row-np.asarray(self.model["means"]))/np.asarray(self.model["scales"]); self.history.append(row); sequence=list(self.history)
        if len(sequence)<self.history.maxlen: sequence=[sequence[0]]*(self.history.maxlen-len(sequence))+sequence
        hybrid=np.concatenate([row,self._embedding(sequence)])[None,:]
        return float(self.booster.predict(xgb.DMatrix(hybrid))[0])
