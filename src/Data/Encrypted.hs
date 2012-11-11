{-# LANGUAGE ExistentialQuantification,
             OverloadedStrings,
             NamedFieldPuns #-}

module Data.Encrypted (
  Encrypted (..),
  ) where

import Data.UUID
import Data.Tagged
import Data.Aeson
import Data.Aeson.Types (Parser)
import Data.Traversable
import           Data.Map (Map)
import qualified Data.Map as M hiding (keys)
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Text.Encoding as E
import           Data.Text.Lazy.Encoding as EL
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.Lazy as LB64
import           Data.Serialize (Serialize)
import qualified Data.Serialize as S

import Crypto.Random.DRBG
import Crypto.Modes
import Crypto.Classes hiding (encode)
import Crypto.Padding

import Test.QuickCheck
import Test.QuickCheck.Gen
import System.Random

import Codec.Compression.Zlib

import Control.Monad
import Control.Error

-- | A box for putting 'BlockCipher k's, useful for JSON encoding
newtype Key k = Key { unKey :: k } deriving (Show, Eq)

-- | A box for putting 'IV k's, useful for JSON encoding
newtype Ivec k = Ivec { unIvec :: IV k } deriving (Show, Eq)

instance BlockCipher k => Serialize (Ivec k) where
  put = S.put . unIvec
  get = fmap Ivec S.get

-- | A little newtype wrapper for documentation purposes. It'll get
-- stripped in compile and I doubt I'll even export it.
newtype Payload = Payload { getBytes :: ByteString }
                deriving (Show, Eq)

-- | Passes through to the underlying 'ByteString'
instance Serialize Payload where
  put = S.put . getBytes
  get = fmap Payload S.get

newtype Id = Id { toUUID :: UUID }
           deriving (Show, Eq, Ord)

-- | A keybox is a box of keys, or, less coyly, a mapping from (UUID,
-- PersonalKey) space to the content key
newtype Keybox k = Keybox { getMap :: Map Id (Encrypted k (Key k)) }
                 deriving (Show, Eq)

-- | An encrypted wrapper around some polymorphic type acting as
-- almost a 'Functor'
data Encrypted k a =
  Encrypted { ivec    :: Ivec k,
              keys    :: Maybe (Keybox k),
              payload :: Payload }
  deriving (Show, Eq)

data Keycard k = Keycard { key :: Id, secret :: Key k }



-- | Encrypt with a single key, a downgraded, "normal" 'Encrypted' box
encrypt :: (BlockCipher k, ToJSON a) =>
           Key k -> Ivec k -> a -> Encrypted k a
encrypt key iv a =
  Encrypted { ivec = iv,
              keys = Nothing,
              payload = Payload $ fst $ cbc' (unKey key) (unIvec iv) s }
  where s = padBlockSize (unKey key) $ B.concat $ L.toChunks $ compress $ encode a

decrypt :: (BlockCipher k, FromJSON a) =>
           Key k -> Encrypted k a -> Maybe a
decrypt = undefined
-- decrypt k (Encrypted { 
--   where contentKey = 

lockAway :: BlockCipher k => Key k -> Keycard k -> Ivec k -> Keybox k
lockAway contentkey (Keycard { key, secret }) iv =
  Keybox $ M.singleton key (encrypt secret iv contentkey)

-- | Encrypt using a 'Keycard', storing the identity and the encrypted
-- content key
encryptAs :: (BlockCipher k, ToJSON a, FromJSON a) 
             => Key k -> Ivec k      -- ^ The content key and its 'IV'
             -> Keycard k -> Ivec k  -- ^ The 'Keycard' and its 'IV'
             -> a -> Encrypted k a -- ^ An 'Encrypted' producer
encryptAs contentkey ivcontent keycard ivcard a =
  (encrypt contentkey ivcontent a) {
    keys = Just $ lockAway contentkey keycard ivcard
    }

-- | Looks up the content key in the 'Keybox' of an 'Encrypted' box
getContentKey :: BlockCipher k => Keycard k -> Encrypted k a -> Maybe (Key k)
getContentKey (Keycard { key, secret }) (Encrypted { keys }) =
  do Keybox map <- keys
     enc <- M.lookup key map
     decrypt secret enc
     

addIdentity :: (BlockCipher k, ToJSON a)
               => Keycard k                      -- ^ An authorized identity
               -> Keycard k -> Ivec k            -- ^ The identity to add
               -> Encrypted k a -> Encrypted k a -- ^ An 'Encrypted' transformer
addIdentity = undefined


-- Serialization instances: JSON

instance FromJSON Id where
  parseJSON (String s) = fmap Id $ justZ $ fromString $ T.unpack s
  parseJSON _          = fail "parse: Data.Encrypted.JSON UUID"

instance ToJSON Id where
  toJSON = String . T.pack . toString . toUUID

-- | A helper function which serializes any serializable value into a
-- JSON String
stringFromSerializable :: Serialize a => a -> Value
stringFromSerializable = String . E.decodeUtf8 . B64.encode . S.encode

-- | The inverse function of 'stringFromSerializable'
serializableFromString :: (Serialize a, MonadPlus m) => Value -> m a
serializableFromString (String s) =
  rightZ . (S.decode <=< B64.decode) . E.encodeUtf8 $ s
serializableFromString _          = mzero

instance BlockCipher k => ToJSON (Key k) where
  toJSON = stringFromSerializable . unKey

instance BlockCipher k => FromJSON (Key k) where
  parseJSON = fmap Key . serializableFromString

instance BlockCipher k => ToJSON (Keybox k) where
  toJSON = toJSON
           . M.mapKeys (EL.decodeUtf8 . LB64.encode . toByteString . toUUID)
           . M.map toJSON
           . getMap


-- | Traverses on the map as a list, so it could be faster if it were
-- in-place instead of having to deconstruct and rebuild the map
-- through an intermediary
instance BlockCipher k => FromJSON (Keybox k) where
  parseJSON = fmap (Keybox . M.fromList)
              . join
              . liftM (traverse doPair . M.toList)
              . parseJSON

doPair :: (BlockCipher k) =>
          (Text, Value) -> Parser (Id, Encrypted k (Key k))
doPair (t, v) = do uuid <- justZ $ fromByteString $ L.fromChunks $ return $ E.encodeUtf8 t
                   enc  <- parseJSON v
                   return (Id uuid, enc)
                   

instance ToJSON Payload where
  toJSON = String . E.decodeUtf8 . B64.encode . getBytes

instance FromJSON Payload where
  parseJSON (String s) = fmap Payload $ rightZ $ B64.decode $ E.encodeUtf8 s
  parseJSON _          = fail "parse: Data.Encrypted.JSON Payload"

instance (FromJSON a, BlockCipher k) => FromJSON (Encrypted k a) where
  parseJSON (Object o) = do
    ivec    <- o .: "ivec" >>= serializableFromString
    keys    <- o .: "keys"
    payload <- o .: "payload" >>= serializableFromString
    return Encrypted { ivec = ivec,
                       keys = keys,
                       payload = payload }
  parseJSON _ = fail "parse: Data.Encrypted FromJSON Encrypted"

instance (ToJSON a, BlockCipher k) => ToJSON (Encrypted k a) where
  toJSON (Encrypted { ivec, keys, payload }) =
    object [ "ivec"    .= stringFromSerializable ivec,
             "keys"    .= toJSON keys,
             "payload" .= stringFromSerializable payload ]



-- Arbitrary instances

-- | Newtype entirely to form the Arbitrary instance
newtype Pair k = P { unPair ::  (Keycard k, Keybox k) }

instance (BlockCipher k) => Arbitrary (Pair k) where
  arbitrary = do
    contentkey <- arbitrary
    key        <- arbitrary
    iv         <- arbitrary
    uuid       <- arbitrary
    let card = Keycard { key = uuid, secret = key }
    return $ P (card, lockAway contentkey card iv)

instance BlockCipher k => Arbitrary (Keycard k) where
  arbitrary = fmap (fst . unPair) arbitrary

instance BlockCipher k => Arbitrary (Keybox k) where
  arbitrary = fmap (snd . unPair) arbitrary

-- | Lifts 'UUID's 'Random' instance
instance Arbitrary Id where
  arbitrary = MkGen $ \g _ -> Id $ fst $ random g

instance BlockCipher k => Arbitrary (Ivec k) where
  arbitrary = do
    ent <- vector $ unTagged (genSeedLength :: Tagged HashDRBG Int)
    let Right g0 = newGen (B.pack ent)
        Right (iv, _) = getIV (g0 :: HashDRBG)
    return (Ivec iv)

-- | NOT CRYPTOGRAPHICALLY SECURE!
instance BlockCipher k => Arbitrary (Key k) where
  arbitrary =
    do let l = keyLength
       Just k <- fmap (buildKey . B.pack) (vector $ untag $ l `div` 8)
       return (Key $ asTaggedTypeOf k l)