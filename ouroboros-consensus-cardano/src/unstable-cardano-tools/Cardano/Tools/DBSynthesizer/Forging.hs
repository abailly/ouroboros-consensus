{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Cardano.Tools.DBSynthesizer.Forging
  ( GenTxs,
    runForge,
  )
where

import           Cardano.Tools.DBSynthesizer.Types (ForgeLimit (..),
                     ForgeResult (..))
import           Control.Monad (when)
import           Control.Monad.Except (runExcept)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import           Control.Tracer as Trace (nullTracer)
import           Data.Either (isRight)
import           Data.Maybe (isJust)
import           Data.Proxy
import           Data.Word (Word64)
import           Ouroboros.Consensus.Block.Abstract as Block
import           Ouroboros.Consensus.Block.Forging as Block (BlockForging (..),
                     ShouldForge (..), checkShouldForge)
import           Ouroboros.Consensus.Config (TopLevelConfig, configConsensus,
                     configLedger)
import           Ouroboros.Consensus.Forecast (forecastFor)
import           Ouroboros.Consensus.HeaderValidation
                     (BasicEnvelopeValidation (..), HeaderState (..))
import           Ouroboros.Consensus.Ledger.Abstract (Validated)
import           Ouroboros.Consensus.Ledger.Basics
import           Ouroboros.Consensus.Ledger.Extended
import           Ouroboros.Consensus.Ledger.SupportsMempool (GenTx)
import           Ouroboros.Consensus.Ledger.SupportsProtocol
import           Ouroboros.Consensus.Protocol.Abstract (ChainDepState,
                     tickChainDepState)
import           Ouroboros.Consensus.Storage.ChainDB.API as ChainDB
                     (AddBlockResult (..), ChainDB, addBlockAsync,
                     blockProcessed, getCurrentChain, getPastLedger)
import qualified Ouroboros.Consensus.Storage.ChainDB.API.Types.InvalidBlockPunishment as InvalidBlockPunishment
                     (noPunishment)
import           Ouroboros.Consensus.Util.IOLike (atomically)
import           Ouroboros.Network.AnchoredFragment as AF (Anchor (..),
                     AnchoredFragment, AnchoredSeq (..), headPoint)

data ForgeState
  = ForgeState
  { currentSlot :: !SlotNo,
    forged :: !Word64,
    currentEpoch :: !Word64,
    processed :: !SlotNo
  }

initialForgeState :: ForgeState
initialForgeState = ForgeState 0 0 0 0

-- | An action to generate transactions for a given block
type GenTxs blk = SlotNo -> TickedLedgerState blk -> IO [Validated (GenTx blk)]

-- DUPLICATE: runForge mirrors forging loop from ouroboros-consensus/src/Ouroboros/Consensus/NodeKernel.hs
-- For an extensive commentary of the forging loop, see there.

runForge ::
     forall blk.
    ( LedgerSupportsProtocol blk )
    => EpochSize
    -> SlotNo
    -> ForgeLimit
    -> ChainDB IO blk
    -> [BlockForging IO blk]
    -> TopLevelConfig blk
    -> GenTxs blk
    -> IO ForgeResult
runForge epochSize_ nextSlot opts chainDB blockForging cfg genTxs = do
  putStrLn $ "--> epoch size: " ++ show epochSize_
  putStrLn $ "--> will process until: " ++ show opts
  endState <- go initialForgeState {currentSlot = nextSlot}
  putStrLn $ "--> forged and adopted " ++ show (forged endState) ++ " blocks; reached " ++ show (currentSlot endState)
  pure $ ForgeResult $ fromIntegral $ forged endState
  where
    epochSize = unEpochSize epochSize_

    forgingDone :: ForgeState -> Bool
    forgingDone = case opts of
      ForgeLimitSlot s -> (s ==) . processed
      ForgeLimitBlock b -> (b ==) . forged
      ForgeLimitEpoch e -> (e ==) . currentEpoch

    go :: ForgeState -> IO ForgeState
    go forgeState
      | forgingDone forgeState = pure forgeState
      | otherwise = do
          let slot = currentSlot forgeState
          isForging <- runExceptT (goSlot slot)
          snapshotState (topLevelConfigCodec cfg) epochSize slot chainDB
          go . nextForgeState forgeState . isRight $ isForging

    nextForgeState :: ForgeState -> Bool -> ForgeState
    nextForgeState ForgeState {currentSlot, forged, currentEpoch, processed} didForge =
      ForgeState
        { currentSlot = currentSlot + 1,
          forged = forged + if didForge then 1 else 0,
          currentEpoch = epoch',
          processed = processed'
        }
      where
        processed' = processed + 1
        epoch' = currentEpoch + if unSlotNo processed' `rem` epochSize == 0 then 1 else 0

    -- just some shims; in this ported code, we use ExceptT instead of WithEarlyExit
    exitEarly' = throwE
    lift = liftIO

    goSlot :: SlotNo -> ExceptT String IO ()
    goSlot currentSlot = do
      -- Figure out which block to connect to
      BlockContext {bcBlockNo, bcPrevPoint} <- getBlockContext currentSlot chainDB

      -- Get corresponding ledger state, ledgder view and ticked 'ChainDepState'
      unticked <- do
        mExtLedger <- lift $ atomically $ ChainDB.getPastLedger chainDB bcPrevPoint
        case mExtLedger of
          Just l -> return l
          Nothing -> do
            exitEarly' "no ledger state"

        ledgerView <-
          case runExcept $ forecastFor
                           (ledgerViewForecastAt
                              (configLedger cfg)
                              (ledgerState unticked))
                           currentSlot of
            Left err -> exitEarly' $ "no ledger view: " ++ show err
            Right lv -> return lv

        let tickedChainDepState :: Ticked (ChainDepState (BlockProtocol blk))
            tickedChainDepState =
                tickChainDepState
                  (configConsensus cfg)
                  ledgerView
                  currentSlot
                  (headerStateChainDep (headerState unticked))

        -- Check if any forger is slot leader
        let
            checkShouldForge' f =
              checkShouldForge f nullTracer cfg currentSlot tickedChainDepState

        checks <- zip blockForging <$> liftIO (mapM checkShouldForge' blockForging)

        (blockForging', proof) <- case [(f, p) | (f, ShouldForge p) <- checks] of
          x:_ -> pure x
          _   -> exitEarly' "NoLeader"

        -- Tick the ledger state for the 'SlotNo' we're producing a block for
        let tickedLedgerState :: Ticked (LedgerState blk)
            tickedLedgerState =
              applyChainTick
                (configLedger cfg)
                (ledgerState unticked)

        -- Let the caller generate transactions
        txs <- lift $ genTxs currentSlot tickedLedgerState

      let tickedChainDepState :: Ticked (ChainDepState (BlockProtocol blk))
          tickedChainDepState =
            tickChainDepState
              (configConsensus cfg)
              ledgerView
              currentSlot
              (headerStateChainDep (headerState unticked))

      -- Check if any forger is slot leader
      let checkShouldForge' f =
            checkShouldForge f nullTracer cfg currentSlot tickedChainDepState

      checks <- zip blockForging <$> liftIO (mapM checkShouldForge' blockForging)

      (blockForging', proof) <- case [(f, p) | (f, ShouldForge p) <- checks] of
        x : _ -> pure x
        _ -> exitEarly' "NoLeader"

      -- Tick the ledger state for the 'SlotNo' we're producing a block for
      let tickedLedgerState :: Ticked (LedgerState blk) DiffMK
          tickedLedgerState =
            applyChainTick
              OmitLedgerEvents
              (configLedger cfg)
              currentSlot
              (ledgerState unticked)

      -- Let the caller generate transactions
      txs <- lift $ withRegistry $ \reg ->
        genTxs
          currentSlot
          ( either (error "Impossible: we are forging on top of a block that the ChainDB cannot create forkers on!") id
              <$> getReadOnlyForkerAtPoint chainDB reg (SpecificPoint bcPrevPoint)
          )
          tickedLedgerState

      -- Actually produce the block
      newBlock <-
        lift $
          Block.forgeBlock
            blockForging'
            cfg
            bcBlockNo
            currentSlot
            tickedLedgerState
            txs
            proof

      -- Add the block to the chain DB (synchronously) and verify adoption
      let noPunish = InvalidBlockPunishment.noPunishment
      result <- lift $ ChainDB.addBlockAsync chainDB noPunish newBlock
      mbCurTip <- lift $ atomically $ ChainDB.blockProcessed result

      case mbCurTip of
        SuccesfullyAddedBlock point | blockPoint newBlock == point -> pure ()
        SuccesfullyAddedBlock point -> exitEarly' $ "block not adopted: " <> show point
        FailedToAddBlock reason -> exitEarly' $ "failed to add block: " <> reason

getBlockContext :: (HasCallStack, GetHeader blk, BasicEnvelopeValidation blk) => SlotNo -> ChainDB IO blk -> ExceptT String IO (BlockContext blk)
getBlockContext currentSlot chainDB = do
  eBlkCtx <-
    liftIO $
      atomically $
        mkCurrentBlockContext currentSlot
          <$> ChainDB.getCurrentChain chainDB
  case eBlkCtx of
    Right blkCtx -> return blkCtx
    Left {} -> throwE "no block context"

snapshotState ::
  forall blk.
  ( HasCallStack,
    EncodeDisk blk (LedgerState blk EmptyMK),
    EncodeDisk blk (ChainDepState (BlockProtocol blk)),
    EncodeDisk blk (AnnTip blk),
    GetHeader blk,
    BasicEnvelopeValidation blk
  ) =>
  CodecConfig blk ->
  Word64 ->
  SlotNo ->
  ChainDB IO blk ->
  IO ()
snapshotState codecConfig epochSize currentSlot@(SlotNo slot) chainDb
  | remainingSlotsInEpoch == 0 && epochNo > 0 = do
      putStrLn $ "--> writing ledger snapshot: " ++ show snapshotPath
      BlockContext {bcPrevPoint = point} <- runExceptT (getBlockContext currentSlot chainDb) >>= either error pure
      extLedgerState <- fromMaybe (error $ "fail to get ledger state for point " <> show point) <$> atomically (ChainDB.getPastLedger chainDb point)
      cleanupSnapshot
      void $ writeExtLedgerState @_ @blk (SomeHasFS fs) encoder snapshotPath extLedgerState
  where
    (epochNo, remainingSlotsInEpoch) = slot `divMod` epochSize
    snapshotPath = mkFsPath ["ledger.snapshot." <> show epochNo]
    encoder = encodeDiskExtLedgerState codecConfig
    fs = ioHasFS @IO (MountPoint ".")
    cleanupSnapshot = do
      fileExists <- doesFileExist fs snapshotPath
      when fileExists $ do
        putStrLn $ "----> remove previous file " <> show snapshotPath
        removeFile fs snapshotPath
snapshotState _ _ _ _ = pure ()

-- | Context required to forge a block
data BlockContext blk = BlockContext
  { bcBlockNo :: !BlockNo,
    bcPrevPoint :: !(Point blk)
  }

-- | Create the 'BlockContext' from the header of the previous block
blockContextFromPrevHeader ::
  (HasHeader (Header blk)) =>
  Header blk ->
  BlockContext blk
blockContextFromPrevHeader hdr =
  BlockContext (succ (blockNo hdr)) (headerPoint hdr)

-- | Determine the 'BlockContext' for a block about to be forged from the
-- current slot, ChainDB chain fragment, and ChainDB tip block number
mkCurrentBlockContext ::
  forall blk.
  ( GetHeader blk,
    BasicEnvelopeValidation blk
  ) =>
  SlotNo ->
  AnchoredFragment (Header blk) ->
  Either () (BlockContext blk)
mkCurrentBlockContext currentSlot c = case c of
  Empty AF.AnchorGenesis ->
    Right $ BlockContext (expectedFirstBlockNo (Proxy @blk)) GenesisPoint
  Empty (AF.Anchor anchorSlot anchorHash anchorBlockNo) ->
    let p :: Point blk = BlockPoint anchorSlot anchorHash
     in if anchorSlot < currentSlot
          then Right $ BlockContext (succ anchorBlockNo) p
          else Left ()
  c' :> hdr -> case blockSlot hdr `compare` currentSlot of
    LT -> Right $ blockContextFromPrevHeader hdr
    GT -> Left ()
    EQ ->
      Right $
        if isJust (headerIsEBB hdr)
          then blockContextFromPrevHeader hdr
          else BlockContext (blockNo hdr) $ castPoint $ AF.headPoint c'
