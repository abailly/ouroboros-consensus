{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}

module Test.Ouroboros.Consensus.Protocol.Praos.Header (genHeader) where

import           Cardano.Crypto.DSIGN
                     (DSIGNAlgorithm (SignKeyDSIGN, genKeyDSIGN), Ed25519DSIGN,
                     deriveVerKeyDSIGN)
import           Cardano.Crypto.Hash (Blake2b_256, Hash, hash)
import qualified Cardano.Crypto.KES as KES
import           Cardano.Crypto.KES.Class (genKeyKES)
import           Cardano.Crypto.Seed (mkSeedFromBytes)
import qualified Cardano.Crypto.VRF as VRF
import qualified Cardano.Crypto.VRF.Praos as VRF
import           Cardano.Ledger.BaseTypes (Nonce (..), ProtVer (..), Version,
                     natVersion)
import           Cardano.Ledger.Keys (VKey (..), signedDSIGN)
import           Cardano.Protocol.TPraos.BHeader (HashHeader (..),
                     PrevHash (..))
import           Cardano.Protocol.TPraos.OCert (KESPeriod (..), OCert (..),
                     OCertSignable (..))
import           Cardano.Slotting.Block (BlockNo (..))
import           Cardano.Slotting.Slot (SlotNo (..))
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Coerce (coerce)
import           Ouroboros.Consensus.Protocol.Praos.Header (Header,
                     HeaderBody (..), pattern Header)
import           Ouroboros.Consensus.Protocol.Praos.VRF (mkInputVRF)
import           Ouroboros.Consensus.Protocol.TPraos (StandardCrypto)
import           Test.QuickCheck (Gen, arbitrary, choose, vectorOf)

type KESKey = KES.SignKeyKES (KES.Sum6KES Ed25519DSIGN Blake2b_256)

newVRFSigningKey :: ByteString -> (VRF.SignKeyVRF VRF.PraosVRF, VRF.VerKeyVRF VRF.PraosVRF)
newVRFSigningKey = VRF.genKeyPairVRF . mkSeedFromBytes

newKESSigningKey :: ByteString -> KESKey
newKESSigningKey = genKeyKES . mkSeedFromBytes

{- | Generate a well-formed header

The header is signed with the KES key, and all the signing keys
generated for the purpose of producing the header are returned.
-}
genHeader :: Gen (Header StandardCrypto, KESKey, SignKeyDSIGN Ed25519DSIGN, VRF.SignKeyVRF VRF.PraosVRF)
genHeader = do
    (body, KESPeriod kesPeriod, kesSignKey, coldSignKey, vrfSignKey) <- genHeaderBody
    let sign = KES.SignedKES $ KES.signKES () kesPeriod body kesSignKey
    pure $ (Header body sign, kesSignKey, coldSignKey, vrfSignKey)

genHeaderBody :: Gen (HeaderBody StandardCrypto, KESPeriod, KESKey, SignKeyDSIGN Ed25519DSIGN, VRF.SignKeyVRF VRF.PraosVRF)
genHeaderBody = do
    coldSk <- genKeyDSIGN . mkSeedFromBytes <$> gen32Bytes
    hbBlockNo <- BlockNo <$> arbitrary
    hbSlotNo <- SlotNo <$> arbitrary
    hbPrev <- BlockHash . HashHeader <$> genHash
    let hbVk = VKey $ deriveVerKeyDSIGN coldSk
    (issuerVrfSk, hbVrfVk) <- newVRFSigningKey <$> gen32Bytes
    nonce <- Nonce <$> genHash
    let rho' = mkInputVRF hbSlotNo nonce
        hbVrfRes = VRF.evalCertified () rho' issuerVrfSk

    hbBodySize <- choose (1000, 90000)
    hbBodyHash <- genHash -- !(Hash crypto EraIndependentBlockBody)
    (hbOCert, kesPeriod, kesSignKey) <- genCert coldSk --  :: !(OCert crypto)
    let hbProtVer = protocolVersionZero
        headerBody = HeaderBody{..}
    pure $ (headerBody, kesPeriod, kesSignKey, coldSk, issuerVrfSk)

protocolVersionZero :: ProtVer
protocolVersionZero = ProtVer versionZero 0
  where
    versionZero :: Version
    versionZero = natVersion @0

genCert :: SignKeyDSIGN Ed25519DSIGN -> Gen (OCert StandardCrypto, KESPeriod, KES.SignKeyKES (KES.Sum6KES Ed25519DSIGN Blake2b_256))
genCert sKeyCold = do
    kesSigningKey <- newKESSigningKey <$> gen32Bytes
    let ocertVkHot = KES.deriveVerKeyKES kesSigningKey
    ocertN <- arbitrary
    keyRegKesPeriod <- KESPeriod <$> arbitrary
    ocertKESPeriod <- KESPeriod <$> arbitrary
    let ocertSigma = signedDSIGN @StandardCrypto sKeyCold (OCertSignable ocertVkHot (fromIntegral $ unKESPeriod ocertKESPeriod) keyRegKesPeriod)
    pure (OCert{..}, ocertKESPeriod, kesSigningKey)

genHash :: Gen (Hash Blake2b_256 a)
genHash = coerce . hash <$> gen32Bytes

gen32Bytes :: Gen ByteString
gen32Bytes = BS.pack <$> vectorOf 32 arbitrary
