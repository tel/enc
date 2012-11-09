{-# LANGUAGE DeriveDataTypeable,
             TemplateHaskell,
             ExistentialQuantification #-}

module Data.Encrypted where

import Data.Data
import Data.UUID
import Data.Aeson
import Data.Tagged
import           Data.Map (Map)
import qualified Data.Map as M
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import           Data.Serialize (Serialize)
import qualified Data.Serialize as S

import Codec.Compression.Zlib

import Crypto.Cipher.AES.Haskell (AES256)
import Crypto.Random.DRBG
import Crypto.Modes
import Crypto.Padding
import Crypto.Classes hiding (encode)

import Test.QuickCheck
import Test.QuickCheck.Gen
import System.Random

import Control.Lens
import Control.Monad
import Control.Error

-- | A box for putting 'BlockCipher k's, useful for JSON encoding
newtype Key k = Key { unKey :: k } deriving (Show, Eq, Data, Typeable)

-- | A little newtype wrapper for documentation purposes. It'll get
-- stripped in compile and I doubt I'll even export it.
newtype Payload = Payload { getBytes :: ByteString }
                deriving (Show, Eq, Data, Typeable)

-- | Passes through to the underlying 'ByteString'
instance Serialize Payload where
  put = S.put . getBytes
  get = fmap Payload S.get

-- | A keybox is a box of keys, or, less coyly, a mapping from (UUID,
-- PersonalKey) space to the content key
newtype Keybox k = Keybox { getMap :: (Map UUID (Encrypted k (Key k))) }
                 deriving (Show, Eq, Data, Typeable)

-- | TODO: Make these opaque but viable? Or remove the Data/Typeable
-- instance of Encrypted
instance Typeable (IV k) where
  typeOf = undefined

-- | TODO: Make these opaque but viable? Or remove the Data/Typeable
-- instance of Encrypted
instance Data (IV k) where
  gunfold = undefined
  toConstr = undefined
  dataTypeOf = undefined

-- | An encrypted wrapper around some polymorphic type acting as
-- almost a 'Functor'
data Encrypted k a =
  Encrypted { ivec    :: IV k,
              keys    :: Maybe (Keybox k),
              payload :: Payload }
  deriving (Show, Eq, Data, Typeable)

data Keycard k = Keycard { key :: UUID, secret :: (Key k) }


-- Arbitrary instances for testing

-- | Lifts 'UUID's 'Random' instance
instance Arbitrary UUID where
  arbitrary = MkGen $ \g _ -> fst $ random g

instance BlockCipher k => Arbitrary (IV k) where
  arbitrary = do
    ent <- vector $ unTagged (genSeedLength :: Tagged HashDRBG Int)
    let Right g0 = newGen (B.pack ent)
        Right (iv, _) = getIV (g0 :: HashDRBG)
    return iv

-- | NOT CRYPTOGRAPHICALLY SECURE!
instance BlockCipher k => Arbitrary (Key k) where
  arbitrary =
    do let l = keyLength
       Just k <- fmap (buildKey . B.pack) (vector $ untag $ l `div` 8)
       return (Key $ asTaggedTypeOf k l)