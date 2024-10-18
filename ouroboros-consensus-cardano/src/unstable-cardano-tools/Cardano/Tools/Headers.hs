{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeApplications #-}

-- | Tooling to generate and validate (Praos) headers.
module Cardano.Tools.Headers where

import Cardano.Crypto.DSIGN (deriveVerKeyDSIGN)
import Cardano.Crypto.VRF (VRFAlgorithm (deriveVerKeyVRF, hashVerKeyVRF))
import Cardano.Ledger.Api (ConwayEra, StandardCrypto)
import Cardano.Ledger.BaseTypes (BoundedRational (boundRational), PositiveUnitInterval, mkActiveSlotCoeff)
import Cardano.Ledger.Coin (Coin (..))
import Cardano.Ledger.Compactible (toCompact)
import Cardano.Ledger.Keys (VKey (..), hashKey)
import Cardano.Ledger.PoolDistr (IndividualPoolStake (..))
import Cardano.Protocol.TPraos.OCert (ocertN)
import Control.Monad.Except (runExcept)
import qualified Data.Aeson as Json
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import Ouroboros.Consensus.Block (validateView)
import Ouroboros.Consensus.Protocol.Praos (
    Praos,
    doValidateKESSignature,
    doValidateVRFSignature,
 )
import Ouroboros.Consensus.Protocol.Praos.Header (Header, hbOCert, pattern Header)
import Ouroboros.Consensus.Shelley.HFEras ()
import Ouroboros.Consensus.Shelley.Ledger (
    ShelleyBlock,
    mkShelleyHeader,
 )

import Ouroboros.Consensus.Shelley.Protocol.Praos ()
import Test.Ouroboros.Consensus.Protocol.Praos.Header (GeneratorContext (..), generateSamples)

type ConwayBlock = ShelleyBlock (Praos StandardCrypto) (ConwayEra StandardCrypto)

-- * Running Generator
data Options = Options

run :: Options -> IO ()
run Options = do
    sample <- generateSamples
    LBS.putStr $ Json.encode sample <> "\n"

data ValidationResult = Valid | Invalid String
    deriving (Eq, Show)

validate :: GeneratorContext -> Header StandardCrypto -> ValidationResult
validate context header =
    case runExcept $ validateKES >> validateVRF of
        Left err -> Invalid (show err)
        Right _ -> Valid
  where
    GeneratorContext{praosSlotsPerKESPeriod, nonce, coldSignKey, vrfSignKey} = context
    -- TODO: get these from the context
    maxKESEvo = 63
    coin = fromJust . toCompact . Coin
    slotCoeff = mkActiveSlotCoeff $ fromJust $ boundRational @PositiveUnitInterval $ 1
    ownsAllStake vrfKey = IndividualPoolStake 1 (coin 1) vrfKey
    poolDistr = Map.fromList [(poolId, ownsAllStake hashVRFKey)]
    poolId = hashKey $ VKey $ deriveVerKeyDSIGN coldSignKey
    hashVRFKey = hashVerKeyVRF $ deriveVerKeyVRF vrfSignKey
    Header body _ = header
    certCounter = ocertN . hbOCert $ body
    ocertCounters = Map.fromList [(poolId, certCounter)]

    headerView = validateView @ConwayBlock undefined (mkShelleyHeader header)
    validateKES = doValidateKESSignature maxKESEvo praosSlotsPerKESPeriod poolDistr ocertCounters headerView
    validateVRF = doValidateVRFSignature nonce poolDistr slotCoeff headerView
