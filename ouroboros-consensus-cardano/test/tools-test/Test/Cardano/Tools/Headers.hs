{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Tools.Headers (tests) where

import Cardano.Tools.Headers (ValidationResult (..), validate)
import qualified Data.Aeson as Json
import Data.Char (isSpace)
import qualified Data.Text as Text
import Test.Ouroboros.Consensus.Protocol.Praos.Header (genContext, genHeader, genSample)
import Test.QuickCheck (Property, forAll, (===))
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

ctor :: (Show e) => Either e a -> String
ctor = \case
    (Left err) ->
        Text.unpack $ head $ concatMap (Text.split isSpace) $ Text.split (== '(') $ Text.pack $ show err
    (Right _) -> error "ctor: Right"

prop_validate_legit_header :: Property
prop_validate_legit_header =
    forAll genContext $ \context ->
        forAll (genHeader context) $ \header ->
            validate context header === Valid
