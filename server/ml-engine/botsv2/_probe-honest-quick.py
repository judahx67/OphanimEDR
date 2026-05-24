import sys
from pathlib import Path
sys.path.insert(0, str(Path('..').resolve()))
sys.path.insert(0, str(Path('/J/THESIS-EDR/server').resolve()))
from model_loader import FrozenModel
from feature_row import build_feature_row

m = FrozenModel(Path("J:/THESIS-EDR/server/ml-engine/botsv2/models/lgbm_xt_stratified_vanilla_sysmon_honest"))
print(f"threshold={m.threshold:.3f}  n_features={len(m.feature_names)}")
print(f"features: {m.feature_names}")
