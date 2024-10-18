module GenHeader.Parsers where

import Cardano.Tools.Headers (Options (..))
import Data.Version (showVersion)
import Options.Applicative (Parser, ParserInfo, command, execParser, helper, hsubparser, info, progDesc, (<**>))
import Paths_ouroboros_consensus_cardano (version)

parseOptions :: IO Options
parseOptions = execParser argsParser

argsParser :: ParserInfo Options
argsParser =
    info
        (optionsParser <**> helper)
        ( progDesc $
            unlines
                [ "gen-header - A utility to generate valid and invalid Praos headers for testing purpose"
                , "version: " <> showVersion version
                ]
        )

optionsParser :: Parser Options
optionsParser =
    hsubparser
        ( command "generate" (info generateOptionsParser (progDesc "Generate Praos headers context and valid/invalid headers"))
            <> command "validate" (info validateOptionsParser (progDesc "Validate a sample of Praos headers within a context"))
        )

validateOptionsParser :: Parser Options
validateOptionsParser = pure Validate

generateOptionsParser :: Parser Options
generateOptionsParser = pure Generate
