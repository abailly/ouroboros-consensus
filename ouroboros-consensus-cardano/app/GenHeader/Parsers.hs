module GenHeader.Parsers (parseOptions) where

import Cardano.Tools.Headers (Options (..))
import Data.Version (showVersion)
import Options.Applicative (
    Parser,
    ParserInfo,
    auto,
    command,
    execParser,
    help,
    helper,
    hsubparser,
    info,
    long,
    metavar,
    option,
    progDesc,
    short,
    (<**>),
 )
import Paths_ouroboros_consensus_cardano (version)

parseOptions :: IO Options
parseOptions = execParser argsParser

argsParser :: ParserInfo Options
argsParser =
    info
        (optionsParser <**> helper)
        ( progDesc $
            unlines
                [ "gen-header - A utility to generate valid and invalid Praos headers & chains for testing purpose"
                , "version: " <> showVersion version
                ]
        )

optionsParser :: Parser Options
optionsParser =
    hsubparser
        ( command "generate" (info generateOptionsParser (progDesc "Generate Praos headers context and valid/invalid headers. Writes JSON formatted context to stdout and headers to stdout."))
            <> command "chain" (info chainOptionsParser (progDesc "Generate a complete chain of headers. Writes JSON formatted headers as a topologically sorted list of headers to stdout."))
            <> command "validate" (info validateOptionsParser (progDesc "Validate a sample of Praos headers within a context. Reads JSON formatted sample from stdin."))
        )

validateOptionsParser :: Parser Options
validateOptionsParser = pure Validate

generateOptionsParser :: Parser Options
generateOptionsParser =
    Generate <$> countParser

chainOptionsParser :: Parser Options
chainOptionsParser =
    Chain <$> countParser

countParser :: Parser Int
countParser =
    option
        auto
        ( long "count"
            <> short 'c'
            <> metavar "INT"
            <> help "Number of headers to generate"
        )
