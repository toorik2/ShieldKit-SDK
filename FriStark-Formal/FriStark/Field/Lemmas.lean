import FriStark.Field.Goldilocks
import FriStark.Field.Ext
import FriStark.Params.V1

namespace FriStark.Field.Lemmas

open FriStark.Field.Goldilocks
open FriStark.Params.V1 (P EXT_NONRES)

/-- 7 is quadratic non-residue mod P (Euler criterion): W^((P-1)/2) ≡ -1. -/
theorem nonres_seven :
    (pow EXT_NONRES ((P - 1) / 2)) = P - 1 := by native_decide

end FriStark.Field.Lemmas
