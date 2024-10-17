{-# LANGUAGE LambdaCase #-}
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
import Data.Char (isSpace)
import Data.Either (isLeft)
import Data.Function ((&))
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import Data.Ratio ((%))
import qualified Data.Text as Text
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
import Test.QuickCheck (Property, choose, forAll, label, (===))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

tests :: TestTree
tests =
    testGroup
        "HeaderValidation"
        [ testProperty "validate legit header" prop_validate_legit_header
        , testProperty "reject incorrect header" prop_reject_incorrect_header
        ]

coin = fromJust . toCompact . Coin

prop_reject_incorrect_header :: Property
prop_reject_incorrect_header =
    let maxKESEvo = 63
        praosSlotsPerKESPeriod = 100
        slotCoeff = mkActiveSlotCoeff $ fromJust $ boundRational @PositiveUnitInterval $ 5 % 20
     in forAll ((% 10000) <$> choose (0, 100)) $ \stakeRatio ->
            forAll (genHeader praosSlotsPerKESPeriod) $ \(header, nonce, _signKeyKES, signColdKey, signKeyVRF) ->
                let poolId = hashKey $ VKey $ deriveVerKeyDSIGN signColdKey
                    hashVRFKey = hashVerKeyVRF $ deriveVerKeyVRF signKeyVRF
                    poolDistr = Map.fromList [(poolId, IndividualPoolStake stakeRatio (coin 1) hashVRFKey)]
                    Header body _ = header
                    certCounter = ocertN . hbOCert $ body
                    ocertCounters = Map.fromList [(poolId, certCounter)]
                    headerView = validateView @ConwayBlock undefined (mkShelleyHeader header)
                    validateKES = doValidateKESSignature maxKESEvo praosSlotsPerKESPeriod poolDistr ocertCounters headerView
                    validateVRF = doValidateVRFSignature nonce poolDistr slotCoeff headerView
                    result = runExcept (validateKES >> validateVRF)
                 in isLeft result & label (ctor result)

ctor :: (Show e) => Either e a -> String
ctor = \case
    (Left err) ->
        Text.unpack $ head $ concatMap (Text.split isSpace) $ Text.split (== '(') $ Text.pack $ show err
    (Right _) -> error "ctor: Right"

prop_validate_legit_header :: Property
prop_validate_legit_header =
    let maxKESEvo = 63
        praosSlotsPerKESPeriod = 100
        slotCoeff = mkActiveSlotCoeff $ fromJust $ boundRational @PositiveUnitInterval $ 1
        ownsAllStake vrfKey = IndividualPoolStake 1 (coin 1) vrfKey
     in forAll (genHeader praosSlotsPerKESPeriod) $ \(header, nonce, _signKeyKES, signColdKey, signKeyVRF) ->
            let poolId = hashKey $ VKey $ deriveVerKeyDSIGN signColdKey
                hashVRFKey = hashVerKeyVRF $ deriveVerKeyVRF signKeyVRF
                poolDistr = Map.fromList [(poolId, ownsAllStake hashVRFKey)]
                Header body _ = header
                certCounter = ocertN . hbOCert $ body
                ocertCounters = Map.fromList [(poolId, certCounter)]
                headerView = validateView @ConwayBlock undefined (mkShelleyHeader header)
                validateKES = doValidateKESSignature maxKESEvo praosSlotsPerKESPeriod poolDistr ocertCounters headerView
                validateVRF = doValidateVRFSignature nonce poolDistr slotCoeff headerView
             in runExcept (validateKES >> validateVRF) === Right ()

type ConwayBlock = ShelleyBlock (Praos StandardCrypto) (ConwayEra StandardCrypto)
