/-
  Rebuild DEEP public selector samples at (x,z) from H-layout via PublicEval.
-/
import FriStark.Domain.PublicEval
import FriStark.Deep.QAt
import FriStark.Field.Ext
import FriStark.Field.Goldilocks

namespace FriStark.Domain.SelRebuild

open FriStark.Domain.PublicEval
open FriStark.Deep.QAt
open FriStark.Field.Ext
open FriStark.Field.Goldilocks (F)

structure HLayout where
  oT : F
  is_full : List F
  is_partial : List F
  is_block_start : List F
  is_reabsorb : List F
  is_range : List F
  is_range_first : List F
  is_range_step : List F
  is_range_last : List F
  rc : List (List F)
  chain : List (List F)
  range_weight : List F

def selAtBase (L : HLayout) (x : F) : SelAtK :=
  {
    is_full := evalAtBase L.is_full L.oT x
    is_partial := evalAtBase L.is_partial L.oT x
    is_block_start := evalAtBase L.is_block_start L.oT x
    is_reabsorb := evalAtBase L.is_reabsorb L.oT x
    is_range := evalAtBase L.is_range L.oT x
    is_range_first := evalAtBase L.is_range_first L.oT x
    is_range_step := evalAtBase L.is_range_step L.oT x
    is_range_last := evalAtBase L.is_range_last L.oT x
    rc := L.rc.map (fun h => evalAtBase h L.oT x)
    chain_minv := L.chain.map (fun h => evalAtBase h L.oT x)
    range_weight := evalAtBase L.range_weight L.oT x
  }

def selMaskAtZ (L : HLayout) (z : E) : SelMaskZ :=
  {
    is_full := evalAtExt L.is_full L.oT z
    is_partial := evalAtExt L.is_partial L.oT z
    is_block_start := evalAtExt L.is_block_start L.oT z
    is_reabsorb := evalAtExt L.is_reabsorb L.oT z
    is_range := evalAtExt L.is_range L.oT z
    is_range_first := evalAtExt L.is_range_first L.oT z
    is_range_step := evalAtExt L.is_range_step L.oT z
    is_range_last := evalAtExt L.is_range_last L.oT z
    rc := L.rc.map (fun h => evalAtExt h L.oT z)
    chain_minv := L.chain.map (fun h => evalAtExt h L.oT z)
  }

def rwAtZg (L : HLayout) (zg : E) : E :=
  evalAtExt L.range_weight L.oT zg

end FriStark.Domain.SelRebuild
