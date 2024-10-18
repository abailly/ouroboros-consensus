-- | This tool generates valid and invalid Cardano headers.
module Main (main) where

import Cardano.Crypto.Init (cryptoInit)
import Data.Version (showVersion)
import Main.Utf8 (withUtf8)
import Options.Applicative (Parser, ParserInfo, execParser, helper, info, progDesc, (<**>))
import Paths_ouroboros_consensus_cardano (version)
import Test.Ouroboros.Consensus.Protocol.Praos.Header (Options (..), run)

main :: IO ()
main = withUtf8 $ do
    cryptoInit
    options <- execParser argsParser
    run options

argsParser :: ParserInfo Options
argsParser =
    info
        (optionsParser <**> helper)
        ( progDesc $
            unlines
                [ "gen-header - A utility to generate valid and invalid Cardano headers for testing purpose"
                , "version: " <> showVersion version
                ]
        )

optionsParser :: Parser Options
optionsParser = pure Options
