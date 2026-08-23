"""PCSA SCORER — Sprint 2 experiment matrix (OpTC, frozen FLASH encoder).

Builds on the S1 GO (pilot silhouette 0.347 / AUROC 0.955, oracle within-host).
Every headline reports the node-type-composition baseline as its honest floor
(pilot Caveat 1) and decomposes the two degradation sources (pilot Caveat 2):

  A. Decomposition on test host 0501 (3 cells, 3 seeds, CIs):
       oracle x within  (ceiling = pilot)
       oracle x cross    (cost of cross-SCENARIO prototypes)
       detector x cross  (realistic operating point: noisy novelty seeds)
  B. within-vs-cross AUROC matrix over all 3 hosts (the generalization wall).
  C. ablations on 0501 oracle x within: PCSA vs raw-kNN (no k-means) vs
       node-only (no assembly) -> does assembly + prototypes each add value?
  D. reconstruction P/R of assembled subgraph vs GT (conditioned on TP seed).

NOT done: closed-set TTP attribution — optc.txt is a flat binary node list with
no per-node TTP labels; fabricating them would be dishonest. Documented limit.

  PYTHONPATH=server/ml-engine/optc python server/ml-engine/optc/pcsa_scorer.py
"""
from __future__ import annotations
import time
from pathlib import Path
import numpy as np
import pcsa_common as pc

SEEDS = [0, 1, 2]
DET_K = None   # detector alarm budget; default = #GT on test host
L = []


def log(s):
    L.append(s); print(s, flush=True)


def ci(vals):
    return f"{np.mean(vals):.3f}±{np.std(vals):.3f}"


def host_assets(host, gt_all):
    d = pc.load_host(host, gt_all)
    d["Z"] = pc.frozen_node_embeddings(d["X"], d["edges"])
    d["adj"] = pc.build_adj(d["edges"], d["n"])
    d["atk_idx"] = np.where(d["gt_mask"])[0]
    return d


def attack_emb(d):
    e, _ = pc.mean_pool(d["atk_idx"], d["adj"], d["Z"]); return e


def benign_query(d, rng):
    """Type-matched benign seed subgraph embeddings + composition vectors."""
    bseed = pc.type_match_benign(d["labels"][d["atk_idx"]], d["labels"], d["gt_mask"], rng)
    e, subs = pc.mean_pool(bseed, d["adj"], d["Z"])
    return e, pc.composition_vec(subs, d["labels"])


def emb_and_comp(seeds, d):
    e, subs = pc.mean_pool(seeds, d["adj"], d["Z"])
    return e, pc.composition_vec(subs, d["labels"])


def main():
    t0 = time.time()
    gt_all = pc.gt_set()
    log(f"=== PCSA SCORER (NEI_CAP={pc.NEI_CAP} MAX_NODES={pc.MAX_NODES} "
        f"N_PROTO={pc.N_PROTO}) ===")
    log("[load] embedding 3 hosts ...")
    H = {h: host_assets(h, gt_all) for h in pc.HOSTS}

    # precompute attack subgraph embeddings + composition per host
    A = {}
    for h, d in H.items():
        ea = attack_emb(d)
        ca = pc.composition_vec([pc.assemble(int(s), d["adj"]) for s in d["atk_idx"]],
                                d["labels"])
        A[h] = {"emb": ea, "comp": ca}

    # ---------- A. decomposition on test host 0501 ----------
    th = "0501"; d = H[th]; others = [h for h in pc.HOSTS if h != th]
    log(f"\n## A. Decomposition (test={th}, proto-cross={others}) "
        f"[emb AUROC | type-hist floor]")
    cross_emb = np.vstack([A[h]["emb"] for h in others])
    cross_comp = np.vstack([A[h]["comp"] for h in others])

    a_within, f_within, a_ocross, f_ocross = [], [], [], []
    for s in SEEDS:
        rng = np.random.default_rng(s)
        # benign query (shared by within & cross oracle cells)
        be, bc = benign_query(d, rng)
        atk = d["atk_idx"].copy(); rng.shuffle(atk)
        half = len(atk) // 2
        pe = attack_emb({**d, "atk_idx": atk[:half]}); qe = attack_emb({**d, "atk_idx": atk[half:]})
        pc_comp = A[th]["comp"]  # not split for comp floor; approx
        # within: proto = test-half attack, query = held-out attack + benign
        q = np.vstack([qe, be]); y = np.r_[np.ones(len(qe)), np.zeros(len(be))]
        a_within.append(pc.auroc(pe, q, y))
        # composition floor within
        qc = np.vstack([pc.composition_vec([pc.assemble(int(i), d["adj"]) for i in atk[half:]],
                                           d["labels"]), bc])
        pcomp = pc.composition_vec([pc.assemble(int(i), d["adj"]) for i in atk[:half]], d["labels"])
        f_within.append(pc.auroc(pcomp, qc, y))
        # oracle x cross: proto = other hosts attack, query = ALL test attack + benign
        qall = np.vstack([A[th]["emb"], be]); yall = np.r_[np.ones(len(A[th]["emb"])), np.zeros(len(be))]
        a_ocross.append(pc.auroc(cross_emb, qall, yall))
        qcall = np.vstack([A[th]["comp"], bc])
        f_ocross.append(pc.auroc(cross_comp, qcall, yall))
    log(f"  oracle x within : {ci(a_within)} | floor {ci(f_within)}")
    log(f"  oracle x cross  : {ci(a_ocross)} | floor {ci(f_ocross)}")

    # detector x cross: top-K novelty alarms as seeds, label by GT, proto=cross
    K = DET_K or int(d["gt_mask"].sum())
    rng = np.random.default_rng(0)
    nov = pc.novelty_scorer(others, gt_all, rng)(d["X"])
    alarms = np.argsort(nov)[::-1][:K]
    alarm_y = d["gt_mask"][alarms].astype(int)
    log(f"  [detector top-{K}: TP={int(alarm_y.sum())} FP={int((1-alarm_y).sum())} "
        f"precision={alarm_y.mean():.3f}]")
    ae, ac = emb_and_comp(alarms, d)
    a_dcross = pc.auroc(cross_emb, ae, alarm_y)
    f_dcross = pc.auroc(cross_comp, ac, alarm_y)
    log(f"  detector x cross: {a_dcross:.3f} | floor {f_dcross:.3f}  "
        f"(triage: rank TP-alarm subgraphs above FP-alarm)")

    # ---------- B. within vs cross matrix, all hosts ----------
    log("\n## B. within-vs-cross AUROC matrix (oracle seeds) [emb | floor]")
    for th in pc.HOSTS:
        d = H[th]; others = [h for h in pc.HOSTS if h != th]
        w, fw, cr, fcr = [], [], [], []
        for s in SEEDS:
            rng = np.random.default_rng(s)
            be, bc = benign_query(d, rng)
            atk = d["atk_idx"].copy(); rng.shuffle(atk); half = len(atk) // 2
            pe = attack_emb({**d, "atk_idx": atk[:half]}); qe = attack_emb({**d, "atk_idx": atk[half:]})
            q = np.vstack([qe, be]); y = np.r_[np.ones(len(qe)), np.zeros(len(be))]
            w.append(pc.auroc(pe, q, y))
            ce = np.vstack([A[h]["emb"] for h in others])
            qall = np.vstack([A[th]["emb"], be]); yall = np.r_[np.ones(len(A[th]["emb"])), np.zeros(len(be))]
            cr.append(pc.auroc(ce, qall, yall))
            cc = np.vstack([A[h]["comp"] for h in others])
            cr_floor = pc.auroc(cc, np.vstack([A[th]["comp"], bc]), yall); fcr.append(cr_floor)
        log(f"  {th}: within {ci(w)}  cross {ci(cr)} | cross-floor {ci(fcr)}")

    # ---------- C. ablations (0501, oracle x within) ----------
    log("\n## C. ablations (test=0501, oracle x within) — marginal value of each part")
    th = "0501"; d = H[th]
    pcsa_v, knn_v, node_v = [], [], []
    for s in SEEDS:
        rng = np.random.default_rng(s)
        atk = d["atk_idx"].copy(); rng.shuffle(atk); half = len(atk) // 2
        bseed = pc.type_match_benign(d["labels"][atk[half:]], d["labels"], d["gt_mask"], rng)
        # subgraph embeddings (assembly path)
        pe = attack_emb({**d, "atk_idx": atk[:half]})
        qe = attack_emb({**d, "atk_idx": atk[half:]})
        be, _ = pc.mean_pool(bseed, d["adj"], d["Z"])
        q = np.vstack([qe, be]); y = np.r_[np.ones(len(qe)), np.zeros(len(be))]
        pcsa_v.append(pc.auroc(pe, q, y, kmeans=True))
        knn_v.append(pc.auroc(pe, q, y, kmeans=False))
        # node-only: no assembly, raw seed node embedding (same seeds)
        pn = d["Z"][atk[:half]]
        qn = np.vstack([d["Z"][atk[half:]], d["Z"][bseed]])
        node_v.append(pc.auroc(pn, qn, y, kmeans=True))
    log(f"  PCSA (k-means proto + k=2 assembly): {ci(pcsa_v)}")
    log(f"  raw-kNN (no k-means, + assembly)   : {ci(knn_v)}")
    log(f"  node-only (k-means, NO assembly)   : {ci(node_v)}")

    # ---------- D. reconstruction P/R (0501, GT seeds) ----------
    log("\n## D. reconstruction vs GT (test=0501, conditioned on GT seed)")
    d = H["0501"]; gtset = set(np.where(d["gt_mask"])[0]); ngt = len(gtset)
    precs, gtcnt, cov = [], [], set()
    for s in d["atk_idx"]:
        sub = pc.assemble(int(s), d["adj"])
        gt_in = gtset & sub
        precs.append(len(gt_in) / len(sub)); gtcnt.append(len(gt_in)); cov |= gt_in
    log(f"  GT-density of assembled subgraph: {np.mean(precs):.3f} "
        f"(mean {np.mean(gtcnt):.1f} GT nodes/subgraph) | total-GT coverage by union: "
        f"{len(cov)}/{ngt}={len(cov)/ngt:.3f} | n_seeds={ngt}")

    log(f"\nDONE ({time.time()-t0:.0f}s)")
    (pc.CODE_ROOT / "_pcsa_scorer.log").write_text("\n".join(L), encoding="utf-8")
    print("-> _pcsa_scorer.log")


if __name__ == "__main__":
    main()
