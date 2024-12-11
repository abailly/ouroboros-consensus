{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Generate Praos chains out of a stake distribution.
module Test.Ouroboros.Consensus.Protocol.Praos.Chain (generateChain) where

import Cardano.Crypto.DSIGN (Ed25519DSIGN, SignKeyDSIGN, deriveVerKeyDSIGN, genKeyDSIGN)
import qualified Cardano.Crypto.KES as KES
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Cardano.Crypto.VRF (deriveVerKeyVRF, hashVerKeyVRF)
import qualified Cardano.Crypto.VRF as VRF
import qualified Cardano.Crypto.VRF.Praos as VRF
import Cardano.Ledger.BaseTypes (ActiveSlotCoeff, BlockNo (..), Nonce (..), PositiveUnitInterval, SlotNo (..), boundRational, mkActiveSlotCoeff)
import Cardano.Ledger.Binary (EncCBOR, serialize')
import Cardano.Ledger.Coin (Coin (..))
import Cardano.Ledger.Compactible (CompactForm, toCompact)
import Cardano.Ledger.Crypto (StandardCrypto)
import Cardano.Ledger.Keys (VKey (..), signedDSIGN)
import Cardano.Ledger.PoolDistr (IndividualPoolStake (..))
import Cardano.Protocol.TPraos.BHeader (HashHeader (..), PrevHash (..), checkLeaderNatValue, prevHashToNonce)
import Cardano.Protocol.TPraos.OCert (KESPeriod (..), OCert (..), OCertSignable (..))
import Control.Monad (foldM, forM)
import Data.Aeson (ToJSON (..), (.=))
import qualified Data.Aeson as Json
import qualified Data.ByteString.Base16 as Base16
import Data.Data (Proxy (..))
import Data.Foldable (maximumBy)
import Data.Function (on)
import Data.Maybe (fromJust)
import Data.Ratio ((%))
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8)
import Data.Word (Word64)
import Ouroboros.Consensus.Protocol.Praos.Header (Header, HeaderBody (..), headerHash, pattern Header)
import Ouroboros.Consensus.Protocol.Praos.VRF (mkInputVRF, vrfLeaderValue)
import Test.Ouroboros.Consensus.Protocol.Praos.Header (KESKey, PoolId, gen32Bytes, genHash, mkPoolId, newKESSigningKey, newVRFSigningKey, protocolVersionZero, testVersion)
import Test.QuickCheck (Gen, Positive (..), arbitrary, choose, elements, generate, oneof)

data ChainContext = ChainContext
    { praosSlotsPerKESPeriod :: !Word64
    , praosMaxKESEvo :: !Word64
    , activeSlotCoeff :: !ActiveSlotCoeff
    , nonce :: !Nonce
    }
    deriving (Eq, Show)

data StakePool = StakePool
    { ocertCounter :: !Word64
    , kesSignKey :: !KESKey
    , coldSignKey :: !(SignKeyDSIGN Ed25519DSIGN)
    , vrfSignKey :: !(VRF.SignKeyVRF VRF.PraosVRF)
    , poolId :: !PoolId
    , individualStake :: !(IndividualPoolStake StandardCrypto)
    }
    deriving (Show)

data Chain
    = Genesis
    | Tip {header :: !(Header StandardCrypto), height :: !BlockNo, parent :: !Chain}
    deriving (Eq, Show)

newtype Chains = Chains [Chain]
    deriving (Eq, Show)

instance ToJSON Chains where
    toJSON = toJSON . fmap asJSON . toHeaderList
      where
        asJSON :: (Header StandardCrypto, BlockNo) -> Json.Value
        asJSON (hdr, hgt) =
            Json.object
                [ "header" .= cborHeader
                , "height" .= hgt
                , "hash" .= headerHash hdr
                , "parent" .= prevHashToNonce (hbPrev hdrBody)
                ]
          where
            Header hdrBody _ = hdr
            cborHeader = toJSONText hdr

toJSONText :: (EncCBOR a) => a -> Text
toJSONText = decodeUtf8 . Base16.encode . serialize' testVersion

toHeaderList :: Chains -> [(Header StandardCrypto, BlockNo)]
toHeaderList (Chains chains) =
    -- TODO dedup and sort topologically
    concatMap asList chains

asList :: Chain -> [(Header StandardCrypto, BlockNo)]
asList = \case
    Genesis -> []
    Tip hdr hgt parent -> (hdr, hgt) : asList parent

instance Eq StakePool where
    a == b =
        ocertCounter a == ocertCounter b
            && serialize' testVersion (kesSignKey a) == serialize' testVersion (kesSignKey b)
            && vrfSignKey a == vrfSignKey b
            && poolId a == poolId b

generateChain :: Int -> IO Chains
generateChain numSlots = Chains <$> generate (genChain $ fromIntegral numSlots)

genChain :: Word64 -> Gen [Chain]
genChain numSlots = do
    stakePools <- genStakePools
    context <- genContext
    genHeaders context stakePools 0 numSlots [] []

genContext :: Gen ChainContext
genContext = do
    nonce <- Nonce <$> genHash
    pure $
        ChainContext
            { praosSlotsPerKESPeriod = 2048
            , praosMaxKESEvo = 63
            , activeSlotCoeff = mkActiveSlotCoeff $ fromJust $ boundRational @PositiveUnitInterval (1 % 20)
            , ..
            }

genStakePools :: Gen [StakePool]
genStakePools =
    arbitrary >>= \(Positive numPools) ->
        foldM (genStakePool 10_000_000_000_000_000) [] (replicate (fromInteger numPools) $ 1 % numPools)

coin :: Integer -> CompactForm Coin
coin = fromJust . toCompact . Coin

genStakePool :: Integer -> [StakePool] -> Rational -> Gen [StakePool]
genStakePool totalStake pools stake = do
    ocertCounter <- choose (10, 100)
    kesSignKey <- newKESSigningKey <$> gen32Bytes
    coldSignKey <- genKeyDSIGN . mkSeedFromBytes <$> gen32Bytes
    vrfSignKey <- fst <$> newVRFSigningKey <$> gen32Bytes
    let poolId = mkPoolId coldSignKey
        vrfKey = hashVerKeyVRF $ deriveVerKeyVRF vrfSignKey
        individualStake = IndividualPoolStake stake (coin $ floor $ toRational totalStake * stake) vrfKey
    pure $ StakePool{..} : pools

genHeaders :: ChainContext -> [StakePool] -> Word64 -> Word64 -> [Chain] -> [Chain] -> Gen [Chain]
genHeaders context stakePools curSlot maxSlot tips acc
    | curSlot >= maxSlot = pure acc
    | otherwise = do
        newTips <- forM stakePools $ \poolContext -> genHeader context poolContext curSlot tips
        genHeaders context stakePools (succ curSlot) maxSlot newTips (newTips <> acc)

{- | Generate header for this pool a this slot.
Could be a new header, or could be one of the tips if the pool does not produce a block
at this slot.
-}
genHeader :: ChainContext -> StakePool -> Word64 -> [Chain] -> Gen Chain
genHeader context@ChainContext{nonce} stakePool curSlot tips
    | isSlotLeader context stakePool curSlot = do
        let parent = selectLongestChain tips
        genNextBlock context stakePool parent (SlotNo curSlot) nonce
    | otherwise =
        -- node catches up with the longest chain, or keeps following a fork
        oneof [pure $ selectLongestChain tips, if null tips then pure Genesis else elements tips]

genNextBlock :: ChainContext -> StakePool -> Chain -> SlotNo -> Nonce -> Gen Chain
genNextBlock ChainContext{praosSlotsPerKESPeriod} StakePool{vrfSignKey, coldSignKey, kesSignKey, ocertCounter} parent hbSlotNo nonce = do
    let hbBlockNo = BlockNo $ blockHeight parent + 1
        rho' = mkInputVRF hbSlotNo nonce
        hbVrfRes = VRF.evalCertified () rho' vrfSignKey
        hbVrfVk = deriveVerKeyVRF vrfSignKey
        hbVk = VKey $ deriveVerKeyDSIGN coldSignKey
        hbPrev = chainHash parent
    hbBodySize <- choose (1000, 90000)
    hbBodyHash <- genHash
    let ocertVkHot = KES.deriveVerKeyKES kesSignKey
        ocertN = ocertCounter
        ocertKESPeriod = KESPeriod $ fromIntegral $ unSlotNo hbSlotNo `div` praosSlotsPerKESPeriod
        ocertSigma = signedDSIGN @StandardCrypto coldSignKey (OCertSignable ocertVkHot ocertN ocertKESPeriod)
        hbOCert = OCert{..}
        hbProtVer = protocolVersionZero
        body = HeaderBody{..}
        sign = KES.SignedKES $ KES.signKES () (unKESPeriod ocertKESPeriod) body kesSignKey

    pure $ Tip (Header body sign) hbBlockNo parent

chainHash :: Chain -> PrevHash StandardCrypto
chainHash = \case
    Genesis -> GenesisHash
    Tip hdr _ _ -> BlockHash . HashHeader $ headerHash hdr

blockHeight :: Chain -> Word64
blockHeight = \case
    Genesis -> 0
    Tip _ (BlockNo h) _ -> h

selectLongestChain :: [Chain] -> Chain
selectLongestChain = \case
    [] -> Genesis
    chains -> maximumBy (compare `on` blockHeight) chains

isSlotLeader :: ChainContext -> StakePool -> Word64 -> Bool
isSlotLeader context StakePool{vrfSignKey, individualStake = IndividualPoolStake{individualPoolStake}} n =
    let slotNo = SlotNo n
        rho' = mkInputVRF slotNo nonce
        certified = VRF.evalCertified () rho' vrfSignKey
        ChainContext{nonce, activeSlotCoeff} = context
     in checkLeaderNatValue (vrfLeaderValue (Proxy @StandardCrypto) certified) individualPoolStake activeSlotCoeff
