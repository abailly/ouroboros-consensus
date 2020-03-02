{-# LANGUAGE DeriveAnyClass             #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE RecordWildCards            #-}

-- | Layout of individual chunks on disk
--
-- This module is not re-exported from the public Chunks API, since it's only
-- relevant internally in the immutable DB.
module Ouroboros.Consensus.Storage.ImmutableDB.Chunks.Layout (
    -- * Relative slots
    RelativeSlot(..) -- TODO: Opaque
  , maxRelativeSlot
  , relativeSlotIsEBB
  , nthRelativeSlot
  , firstRelativeSlot
  , nextRelativeSlot
    -- * Slots within a chunk
  , ChunkSlot(..)
    -- ** Translation /to/ 'ChunkSlot'
  , chunkSlotForUnknownBlock
  , chunkSlotForRegularBlock
  , chunkSlotForBoundaryBlock
  , chunkSlotForBlockOrEBB
    -- ** Translation /from/ 'ChunkSlot'
  , chunkSlotToSlot
  , chunkSlotToBlockOrEBB
    -- ** Support for EBBs
  , slotNoOfEBB
  ) where

import           Data.Word
import           GHC.Generics (Generic)

import           Cardano.Prelude (NoUnexpectedThunks)
import           Cardano.Slotting.Slot

import           Ouroboros.Consensus.Block.EBB
-- import           Ouroboros.Consensus.Storage.Common
import           Ouroboros.Consensus.Storage.ImmutableDB.Types (BlockOrEBB (..))

-- Most types in the Chunks interface are opaque in the public API, since their
-- interpretation is subject to layout decisions. In this module we /make/ those
-- layout decisions, however, and so here we need access to the internal types.
import           Ouroboros.Consensus.Storage.ImmutableDB.Chunks.Internal

{-------------------------------------------------------------------------------
  Relative slots
-------------------------------------------------------------------------------}

-- | A /relative/ slot within a chunk
--
-- TODO: This should be opaque.
newtype RelativeSlot = RelativeSlot { unRelativeSlot :: Word64 }
  deriving stock   (Eq, Ord, Show, Generic)
  deriving newtype (NoUnexpectedThunks)

-- | The last relative slot within a chunk of the given size
--
-- Relative slot 0 is reserved for the EBB and regular relative slots start at
-- 1, so the last relative slot is equal to the chunk size.
maxRelativeSlot :: ChunkSize -> RelativeSlot
maxRelativeSlot (ChunkSize sz) = RelativeSlot sz

-- | Is this relative slot reserved for an EBB?
relativeSlotIsEBB :: RelativeSlot -> IsEBB
relativeSlotIsEBB (RelativeSlot s) = if s == 0 then IsEBB else IsNotEBB

-- | The @n@'th relative slot
--
-- NOTE: @relativeSlotIsEBB (nthRelativeSlot 0)@.
nthRelativeSlot :: Integral a => a -> RelativeSlot
nthRelativeSlot = RelativeSlot . fromIntegral

-- | The first relative slot
--
-- NOTE: @relativeSlotIsEBB firstRelativeSlot@
firstRelativeSlot :: RelativeSlot
firstRelativeSlot = RelativeSlot 0

-- | Next relative slot
--
-- TODO: We should record the ChunkSize along with the RelativeSlot, so that
-- we can do a bounds check here.
nextRelativeSlot :: RelativeSlot -> RelativeSlot
nextRelativeSlot (RelativeSlot s) = RelativeSlot (succ s)

{-------------------------------------------------------------------------------
  Slot within an epoch

  TODO: These should all be renamed.
-------------------------------------------------------------------------------}

-- | Uniquely identity a block within the immutable DB
data ChunkSlot = ChunkSlot
  { chunkIndex    :: !EpochNo
  , chunkRelative :: !RelativeSlot
  } deriving (Eq, Ord, Generic, NoUnexpectedThunks)

instance Show ChunkSlot where
  show (ChunkSlot (EpochNo e) (RelativeSlot s)) = show (e, s)

{-------------------------------------------------------------------------------
  Translation /to/ 'ChunkSlot'
-------------------------------------------------------------------------------}

-- | Chunk slot for an unknown block
--
-- This returns /two/ 'ChunkSlot's: one in case the block could be an EBB,
-- and one in case the block is a regular block.
chunkSlotForUnknownBlock :: ChunkInfo -> SlotNo -> (Maybe ChunkSlot, ChunkSlot)
chunkSlotForUnknownBlock ci slot = (
      if chunkRelative ifRegular == RelativeSlot 1
        then Just $ chunkSlotForBoundaryBlock (chunkIndex ifRegular)
        else Nothing
    , ifRegular
    )
  where
    ifRegular = chunkSlotForRegularBlock ci slot

-- | Chunk slot for a regular block (i.e., not an EBB)
chunkSlotForRegularBlock :: ChunkInfo -> SlotNo -> ChunkSlot
chunkSlotForRegularBlock ci (SlotNo absSlot) = ChunkSlot{..}
  where
    chunkIndex    = epochInfoEpoch ci (SlotNo absSlot)
    SlotNo first  = epochInfoFirst ci chunkIndex
    chunkRelative = RelativeSlot (absSlot - first + 1)

-- | Chunk slot for EBB
chunkSlotForBoundaryBlock :: EpochNo -> ChunkSlot
chunkSlotForBoundaryBlock e = ChunkSlot e firstRelativeSlot

-- | Chunk slot for 'BlockOrEBB'
chunkSlotForBlockOrEBB :: ChunkInfo -> BlockOrEBB -> ChunkSlot
chunkSlotForBlockOrEBB ci = \case
    Block slot  -> chunkSlotForRegularBlock ci slot
    EBB   epoch -> chunkSlotForBoundaryBlock epoch

{-------------------------------------------------------------------------------
  Translation /from/ 'ChunkSlot'
-------------------------------------------------------------------------------}

-- | From relative to absolute slot
--
-- This can be used for EBBs and regular blocks, since they don't share a
-- relative slot.
chunkSlotToSlot :: ChunkInfo -> ChunkSlot -> SlotNo
chunkSlotToSlot chunkInfo (ChunkSlot epoch (RelativeSlot relSlot)) =
    let SlotNo first = epochInfoFirst chunkInfo epoch
    -- EBB and first block share the first slot
    in SlotNo $ if relSlot == 0 then first
                                else first + relSlot - 1

chunkSlotToBlockOrEBB :: ChunkInfo -> ChunkSlot -> BlockOrEBB
chunkSlotToBlockOrEBB chunkInfo epochSlot@(ChunkSlot epoch relSlot) =
    case relativeSlotIsEBB relSlot of
      IsEBB    -> EBB epoch
      IsNotEBB -> Block $ chunkSlotToSlot chunkInfo epochSlot

{-------------------------------------------------------------------------------
  Support for EBBs
-------------------------------------------------------------------------------}

slotNoOfEBB :: ChunkInfo -> EpochNo -> SlotNo
slotNoOfEBB ci = chunkSlotToSlot ci . chunkSlotForBoundaryBlock
