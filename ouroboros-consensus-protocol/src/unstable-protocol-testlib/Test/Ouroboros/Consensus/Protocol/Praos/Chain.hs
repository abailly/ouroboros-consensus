{-# LANGUAGE InstanceSigs #-}
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

import           Cardano.Crypto.DSIGN (Ed25519DSIGN, SignKeyDSIGN,
                     deriveVerKeyDSIGN, genKeyDSIGN)
import qualified Cardano.Crypto.KES as KES
import           Cardano.Crypto.Seed (mkSeedFromBytes)
import           Cardano.Crypto.VRF (deriveVerKeyVRF, hashVerKeyVRF)
import qualified Cardano.Crypto.VRF as VRF
import qualified Cardano.Crypto.VRF.Praos as VRF
import           Cardano.Ledger.BaseTypes (ActiveSlotCoeff, BlockNo (..),
                     Nonce (..), PositiveUnitInterval, SlotNo (..),
                     boundRational, mkActiveSlotCoeff)
import           Cardano.Ledger.Binary (EncCBOR, serialize')
import           Cardano.Ledger.Coin (Coin (..))
import           Cardano.Ledger.Compactible (CompactForm, toCompact)
import           Cardano.Ledger.Crypto (StandardCrypto)
import           Cardano.Ledger.Keys (VKey (..), signedDSIGN)
import           Cardano.Ledger.PoolDistr (IndividualPoolStake (..))
import           Cardano.Protocol.TPraos.BHeader (HashHeader (..),
                     PrevHash (..), checkLeaderNatValue, prevHashToNonce)
import           Cardano.Protocol.TPraos.OCert (KESPeriod (..), OCert (..),
                     OCertSignable (..))
import           Control.Monad (foldM)
import           Control.Monad.State (StateT, evalStateT, get, gets, lift,
                     modify')
import           Data.Aeson (ToJSON (..), (.=))
import qualified Data.Aeson as Json
import qualified Data.ByteString.Base16 as Base16
import           Data.Data (Proxy (..))
import           Data.Foldable (maximumBy)
import           Data.Function (on)
import qualified Data.IntMap as IntMap
import           Data.Maybe (fromJust, mapMaybe)
import           Data.Ratio ((%))
import qualified Data.Set as Set
import           Data.Text (Text)
import           Data.Text.Encoding (decodeUtf8)
import           Data.Word (Word64)
import           Ouroboros.Consensus.Protocol.Praos.Header (Header,
                     HeaderBody (..), headerHash, pattern Header)
import           Ouroboros.Consensus.Protocol.Praos.VRF (mkInputVRF,
                     vrfLeaderValue)
import           Test.Ouroboros.Consensus.Protocol.Praos.Header (KESKey, PoolId,
                     gen32Bytes, genHash, mkPoolId, newKESSigningKey,
                     newVRFSigningKey, protocolVersionZero, testVersion)
import           Test.QuickCheck (Gen, Positive (..), arbitrary, choose,
                     generate)

data ChainContext = ChainContext
    { praosSlotsPerKESPeriod :: !Word64
    , praosMaxKESEvo         :: !Word64
    , activeSlotCoeff        :: !ActiveSlotCoeff
    , nonce                  :: !Nonce
    }
    deriving (Eq, Show)

data Chain
    = Genesis
    | Tip !(Header StandardCrypto) !BlockNo !Chain
    deriving (Show)

instance Eq Chain where
    Genesis == Genesis          = True
    Tip hdr _ _ == Tip hdr' _ _ = headerHash hdr == headerHash hdr'
    _ == _                      = False

instance Ord Chain where
    compare :: Chain -> Chain -> Ordering
    compare Genesis Genesis = EQ
    compare _ Genesis = GT
    compare Genesis _ = LT
    compare (Tip hdr _ _) (Tip hdr' _ _) =
        compare (headerHash hdr) (headerHash hdr')

newtype Chains = Chains {unChains :: (IntMap.IntMap (Set.Set Chain))}
    deriving (Eq, Show)

instance ToJSON Chains where
    toJSON = toJSON . fmap asJSON . toHeaderList
      where
        asJSON :: (Header StandardCrypto, BlockNo) -> Json.Value
        asJSON (hdr, hgt) =
            Json.object
                [ "header" .= cborHeader
                , "slot" .= hbSlotNo hdrBody
                , "height" .= hgt
                , "hash" .= headerHash hdr
                , "parent" .= prevHashToNonce (hbPrev hdrBody)
                ]
          where
            Header hdrBody _ = hdr
            cborHeader = toJSONText hdr

mkChains :: [Chain] -> Chains
mkChains chains = chains <+> Chains mempty

(<+>) :: [Chain] -> Chains -> Chains
[] <+> chains = chains
cs <+> chains = foldr (+>) chains cs

(+>) :: Chain -> Chains -> Chains
Genesis +> chains = chains
c@(Tip hdr _ parent) +> chains = Chains $ IntMap.insertWith (<>) (fromIntegral slot) (Set.singleton c) (unChains $ parent +> chains)
  where
    Header HeaderBody{hbSlotNo = SlotNo slot} _ = hdr

toJSONText :: (EncCBOR a) => a -> Text
toJSONText = decodeUtf8 . Base16.encode . serialize' testVersion

toHeaderList :: Chains -> [(Header StandardCrypto, BlockNo)]
toHeaderList (Chains chains) =
    fst $ IntMap.mapAccum asHeadersList [] chains
  where
    asList :: Chain -> Maybe (Header StandardCrypto, BlockNo)
    asList = \case
        Genesis -> Nothing
        Tip hdr hgt _ -> Just (hdr, hgt)

    asHeadersList :: [(Header StandardCrypto, BlockNo)] -> Set.Set Chain -> ([(Header StandardCrypto, BlockNo)], IntMap.IntMap [Chain])
    asHeadersList acc cs = (acc <> mapMaybe asList (Set.toList cs), mempty)

data StakePool = StakePool
    { ocertCounter    :: !Word64
    , kesSignKey      :: !KESKey
    , coldSignKey     :: !(SignKeyDSIGN Ed25519DSIGN)
    , vrfSignKey      :: !(VRF.SignKeyVRF VRF.PraosVRF)
    , poolId          :: !PoolId
    , individualStake :: !(IndividualPoolStake StandardCrypto)
    , poolIdx         :: !Int
    , chain           :: !Chain
    }
    deriving (Show)

instance Eq StakePool where
    a == b =
        ocertCounter a == ocertCounter b
            && serialize' testVersion (kesSignKey a) == serialize' testVersion (kesSignKey b)
            && vrfSignKey a == vrfSignKey b
            && poolId a == poolId b
            && individualStake a == individualStake b

{- | Decision procedure to select current best chain for a stake pool.
Such a strategy mimics the true behaviour of the system where honest nodes
diffuse  blocks and select the longest chain they are aware of whereas
adversaries may try to create forks.
-}
type Strategy = Word64 -> StakePool -> StateT SPOs Gen Chain

{- | A very simple strategy which assumes diffusion is perfect and all
nodes always select the longest chain from all the chains.
-}
noAdversariesStrategy :: Strategy
noAdversariesStrategy _curSlot _stakePool = do
    SPOs spos <- get
    lift $ pure $ selectLongestChain $ fmap chain spos

generateChain :: Int -> IO Chains
generateChain numSlots = generate (genChain $ fromIntegral numSlots)

genChain :: Word64 -> Gen Chains
genChain numSlots = do
    stakePools <- genStakePools
    context <- genContext
    genHeaders noAdversariesStrategy context 0 numSlots `evalStateT` SPOs stakePools

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
        foldM (genStakePool numPools 10_000_000_000_000_000) [] [1 .. fromIntegral numPools]

coin :: Integer -> CompactForm Coin
coin = fromJust . toCompact . Coin

genStakePool :: Integer -> Integer -> [StakePool] -> Int -> Gen [StakePool]
genStakePool numPools totalStake pools poolIdx = do
    ocertCounter <- choose (10, 100)
    kesSignKey <- newKESSigningKey <$> gen32Bytes
    coldSignKey <- genKeyDSIGN . mkSeedFromBytes <$> gen32Bytes
    vrfSignKey <- fst <$> newVRFSigningKey <$> gen32Bytes
    let stake = 1 % numPools
        poolId = mkPoolId coldSignKey
        vrfKey = hashVerKeyVRF $ deriveVerKeyVRF vrfSignKey
        individualStake = IndividualPoolStake stake (coin $ floor $ toRational totalStake * stake) vrfKey
        chain = Genesis
    pure $ StakePool{..} : pools

newtype SPOs = SPOs {spos :: [StakePool]}
    deriving (Show)

genHeaders :: Strategy -> ChainContext -> Word64 -> Word64 -> StateT SPOs Gen Chains
genHeaders strategy context curSlot maxSlot
    | curSlot >= maxSlot = gets spos >>= pure . mkChains . map chain
    | otherwise = do
        gets spos >>= mapM_ (genHeader strategy context curSlot)
        genHeaders strategy context (succ curSlot) maxSlot

{- | Generate header for this pool a this slot.
Could be a new header, or could be one of the tips if the pool does not produce a block
at this slot.
-}
genHeader :: Strategy -> ChainContext -> Word64 -> StakePool -> StateT SPOs Gen Chain
genHeader strategy context@ChainContext{nonce} curSlot stakePool
    | isSlotLeader context stakePool curSlot =
        strategy curSlot stakePool
            >>= lift . genNextBlock context stakePool (SlotNo curSlot) nonce
            >>= updateSPOChain stakePool
    | otherwise =
        strategy curSlot stakePool
            >>= updateSPOChain stakePool
  where
    updateSPOChain :: StakePool -> Chain -> StateT SPOs Gen Chain
    updateSPOChain spo chain = do
        modify' $ \(SPOs spos) -> SPOs $ updateChain spo chain spos
        return chain

updateChain :: StakePool -> Chain -> [StakePool] -> [StakePool]
updateChain spo chain = map $ \sp -> if poolId sp == poolId spo then sp{chain} else sp

genNextBlock :: ChainContext -> StakePool -> SlotNo -> Nonce -> Chain -> Gen Chain
genNextBlock ChainContext{praosSlotsPerKESPeriod} StakePool{vrfSignKey, coldSignKey, kesSignKey, ocertCounter} hbSlotNo nonce parent = do
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
