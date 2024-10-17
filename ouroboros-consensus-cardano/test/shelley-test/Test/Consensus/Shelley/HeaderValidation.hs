{-# LANGUAGE TypeApplications #-}

module Test.Consensus.Shelley.HeaderValidation (tests) where

import           Cardano.Ledger.Coin (Coin (..))
import           Cardano.Ledger.Compactible (toCompact)
import           Cardano.Ledger.PoolDistr (PoolDistr (..))
import           Control.Monad.Except (runExcept)
import qualified Data.Map as Map
import           Data.Maybe (fromJust)
import           Ouroboros.Consensus.Block (validateView)
import           Ouroboros.Consensus.Cardano.Block (ConwayEra, StandardCrypto)
import           Ouroboros.Consensus.Protocol.Praos (Praos,
                     doValidateKESSignature)
import           Ouroboros.Consensus.Shelley.HFEras ()
import           Ouroboros.Consensus.Shelley.Ledger (ShelleyBlock,
                     mkShelleyHeader)
import           Ouroboros.Consensus.Shelley.Protocol.Abstract
                     (protocolHeaderView)
import           Ouroboros.Consensus.Shelley.Protocol.Praos ()
import           Test.Ouroboros.Consensus.Protocol.Praos.Header (genHeader)
import           Test.QuickCheck (Property, forAll, (===))
import           Test.Tasty (TestTree, testGroup)
import           Test.Tasty.QuickCheck (testProperty)

tests :: TestTree
tests =
    testGroup
        "HeaderValidation"
        [ testProperty "validate legit header" prop_validate_legit_header
        ]

prop_validate_legit_header :: Property
prop_validate_legit_header =
    forAll genHeader $ \(header, signKeyKES, signColdKey, signKeyVRF) ->
        let maxKESEvo = 63
            praosSlotsPerKESPeriod = 100
            lvPoolDistr = PoolDistr{unPoolDistr = Map.fromList [], pdTotalActiveStake = fromJust (toCompact (Coin 12))}
            ocertCounters = mempty
            headerView = validateView @(ShelleyBlock (Praos StandardCrypto) (ConwayEra StandardCrypto)) undefined (mkShelleyHeader header)
         in runExcept (doValidateKESSignature maxKESEvo praosSlotsPerKESPeriod lvPoolDistr ocertCounters headerView) === Right ()
