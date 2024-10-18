{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}

module Test.Cardano.Tools.Headers (tests) where

import Cardano.Tools.Headers (ValidationResult (..), validate)
import qualified Data.Aeson as Json
import Data.Function ((&))
import qualified Data.Text.Lazy as LT
import Data.Text.Lazy.Encoding (decodeUtf8)
import Test.Ouroboros.Consensus.Protocol.Praos.Header (
    Sample (..),
    genSample,
    shrinkSample,
 )
import Test.QuickCheck (
    Property,
    conjoin,
    counterexample,
    forAll,
    forAllBlind,
    forAllShrinkBlind,
    label,
    property,
    shrink,
    (===),
 )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

tests :: TestTree
tests =
    testGroup
        "HeaderValidation"
        [ testProperty "roundtrip To/FromJSON samples" prop_roundtrip_json_samples
        , testProperty "validate legit header" prop_validate_legit_header
        ]

prop_roundtrip_json_samples :: Property
prop_roundtrip_json_samples =
    forAll genSample $ \sample ->
        let encoded = Json.encode sample
            decoded = Json.eitherDecode encoded
         in decoded === Right sample

matchExpectedValidationResult :: Sample -> Property
matchExpectedValidationResult Sample{context, headers} =
    let results = map (validate context) headers
        toProp = \case
            Valid mut -> property True & label (show mut)
            Invalid mut err -> property False & counterexample ("Expected: " <> show mut <> "\nError: " <> err)
     in conjoin (map toProp results)

prop_validate_legit_header :: Property
prop_validate_legit_header =
    forAllShrinkBlind genSample shrinkSample $ \sample ->
        matchExpectedValidationResult sample
            & counterexample (LT.unpack $ decodeUtf8 $ Json.encode sample)
