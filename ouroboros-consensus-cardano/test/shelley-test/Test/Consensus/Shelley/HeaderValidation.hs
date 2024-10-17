{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeApplications #-}

module Test.Consensus.Shelley.HeaderValidation (tests) where

import Cardano.Crypto.DSIGN (deriveVerKeyDSIGN)
import Cardano.Crypto.Hash (hash)
import Cardano.Crypto.VRF (VRFAlgorithm (deriveVerKeyVRF, hashVerKeyVRF))
import Cardano.Ledger.BaseTypes (BoundedRational (boundRational), PositiveUnitInterval, UnitInterval, mkActiveSlotCoeff)
import Cardano.Ledger.Coin (Coin (..))
import Cardano.Ledger.Compactible (toCompact)
import Cardano.Ledger.Keys (VKey (..), hashKey)
import Cardano.Ledger.PoolDistr (IndividualPoolStake (..), PoolDistr (..))
import Cardano.Protocol.TPraos.OCert (ocertN)
import Control.Monad.Except (runExcept)
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import Data.Ratio ((%))
import Ouroboros.Consensus.Block (validateView)
import Ouroboros.Consensus.Cardano.Block (ConwayEra, StandardCrypto)
import Ouroboros.Consensus.Protocol.Praos (
    Praos,
    doValidateKESSignature,
    doValidateVRFSignature,
 )
import Ouroboros.Consensus.Protocol.Praos.Header (hbOCert, pattern Header)
import Ouroboros.Consensus.Shelley.HFEras ()
import Ouroboros.Consensus.Shelley.Ledger (
    ShelleyBlock,
    mkShelleyHeader,
 )
import Ouroboros.Consensus.Shelley.Protocol.Abstract (
    protocolHeaderView,
 )
import Ouroboros.Consensus.Shelley.Protocol.Praos ()
import Test.Ouroboros.Consensus.Protocol.Praos.Header (genHeader)
import Test.QuickCheck (Property, forAll, (===))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

tests :: TestTree
tests =
    testGroup
        "HeaderValidation"
        [ testProperty "validate legit header" prop_validate_legit_header
        ]

prop_validate_legit_header :: Property
prop_validate_legit_header =
    let maxKESEvo = 63
        praosSlotsPerKESPeriod = 100
     in forAll (genHeader praosSlotsPerKESPeriod) $ \(header, nonce, signKeyKES, signColdKey, signKeyVRF) ->
            let poolId = hashKey $ VKey $ deriveVerKeyDSIGN signColdKey
                hashVRFKey = hashVerKeyVRF $ deriveVerKeyVRF signKeyVRF
                poolDistr = Map.fromList [(poolId, IndividualPoolStake 1 (fromJust (toCompact (Coin 100))) hashVRFKey)]
                Header body _ = header
                certCounter = ocertN . hbOCert $ body
                ocertCounters = Map.fromList [(poolId, certCounter)]
                headerView = validateView @(ShelleyBlock (Praos StandardCrypto) (ConwayEra StandardCrypto)) undefined (mkShelleyHeader header)
                validateKES = doValidateKESSignature maxKESEvo praosSlotsPerKESPeriod poolDistr ocertCounters headerView
                slotCoeff = mkActiveSlotCoeff $ fromJust $ boundRational @PositiveUnitInterval $ 1
                validateVRF = doValidateVRFSignature nonce poolDistr slotCoeff headerView
             in runExcept (validateKES >> validateVRF) === Right ()
