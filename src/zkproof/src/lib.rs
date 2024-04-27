// We make sure this pallet uses `no_std` for compiling to Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub use scale_info::prelude::vec::Vec;

// All pallet logic is defined in its own module and must be annotated by the `pallet` attribute.
#[frame_support::pallet]
pub mod pallet {
    // Import various useful types required by all FRAME pallets.
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// The pallet's configuration trait.
    ///
    /// All our types and constants a pallet depends on must be declared here.
    /// These types are defined generically and made concrete when the pallet is declared in the
    /// `runtime/src/lib.rs` file of your chain.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type MaxJsonLength: Get<u32>;
    }

    //pub type ZkProofData<T: Config> = StorageValue<_, BoundedVec<u8, T::MaxJsonLength>, ValueQuery>;
    #[pallet::storage]
    pub type ZkProofData<T: Config> = StorageMap<_, Twox64Concat, T::Hash, BoundedVec<u8, T::MaxJsonLength>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Un événement pour notifier que des données JSON ont été stockées.
        ZkProofStored {
            json: BoundedVec<u8, T::MaxJsonLength>,
            who: T::AccountId,
            hash: T::Hash,
        },

        ZkProofRetrieved(T::Hash, Vec<u8>),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Erreur levée si la taille des données JSON dépasse la limite maximale.
        ZkProofTooLarge
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Stocke les données JSON dans la blockchain.
        #[pallet::weight(10_000)]
        pub fn store_zk_proof(origin: OriginFor<T>, json: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            use frame_support::sp_runtime::traits::Hash;
            // Conversion du Vec<u8> en BoundedVec<u8>, en vérifiant que la taille ne dépasse pas la limite.
            let proof_hash = T::Hashing::hash(&json);
            log::info!("Storing ZK proof with hash: {:?}", proof_hash);

            let bounded_json = BoundedVec::try_from(json).map_err(|_| Error::<T>::ZkProofTooLarge)?;

            // Stockage des données JSON.
            //ZkProofData::<T>::put(&bounded_json);
            ZkProofData::<T>::insert(proof_hash, bounded_json.clone());

            // Émission d'un événement après la mise à jour du stockage.
            Self::deposit_event(Event::ZkProofStored { json: bounded_json, who, hash: proof_hash });

            Ok(())
        }

        #[pallet::weight(10_000)]
        pub fn retrieve_all_zk_proofs(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
            let _who = ensure_signed(origin)?;

            for (proof_hash, zk_proof) in ZkProofData::<T>::iter() {
                Self::deposit_event(Event::ZkProofRetrieved(proof_hash, zk_proof.to_vec()));
            }

            Ok(().into())
        }
    }
}