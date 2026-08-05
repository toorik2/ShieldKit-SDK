import FriStark.Binding.Presence
namespace FriStark.Binding.Blob
open FriStark.Binding.Presence
/-- Blob role is index 0 (FS commitment carrier). -/
def blobIndex (m : BindingModel) : Nat := m.blobIndex
#guard blobIndex { roles := [], freeWitnesses := [], sourcedFromBlob := [], bindMode := "locking" } == 0
end FriStark.Binding.Blob
