{-# LANGUAGE OverloadedStrings, NamedFieldPuns #-}

module Data.Encrypted.JSON where

import Data.Encrypted

import Data.UUID
import Data.Aeson
import Data.Traversable
import qualified Data.Map as M hiding (keys)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Text.Encoding as E
import           Data.Text.Lazy.Encoding as EL
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.Lazy as LB64
import           Data.Serialize (Serialize)
import qualified Data.Serialize as S
import Codec.Compression.Zlib

import Crypto.Classes (BlockCipher)
import Crypto.Modes
import Crypto.Padding

import Control.Monad
import Control.Error

import Test.QuickCheck

instance FromJSON UUID where
  parseJSON (String s) = justZ $ fromString $ T.unpack s
  parseJSON _          = fail "parse: Data.Encrypted.JSON UUID"

instance ToJSON UUID where
  toJSON = String . T.pack . toString

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
           . M.mapKeys (EL.decodeUtf8 . LB64.encode . toByteString)
           . M.map toJSON
           . getMap

-- | Traverses on the map as a list, so it could be faster if it were
-- in-place instead of having to deconstruct and rebuild the map
-- through an intermediary
instance BlockCipher k => FromJSON (Keybox k) where
  parseJSON = fmap (Keybox . M.fromList)
              . join
              . liftM (justZ . traverse doPair . M.toList)
              . parseJSON

doPair :: BlockCipher k => (Text, Value) -> Maybe (UUID, Encrypted k (Key k))
doPair = undefined

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

instance (ToJSON a, BlockCipher k) => ToJSON (Encrypted k a) where
  toJSON (Encrypted { ivec, keys, payload }) =
    object [ "ivec"    .= (stringFromSerializable ivec),
             "keys"    .= (toJSON keys),
             "payload" .= (stringFromSerializable payload) ]

-- | Encrypt with a single key, a downgraded, "normal" 'Encrypted' box
encrypt :: (BlockCipher k, ToJSON a) =>
           Key k -> IV k -> a -> Encrypted k a
encrypt key iv a =
  Encrypted { ivec = iv,
              keys = Nothing,
              payload = Payload $ fst $ cbc' (unKey key) iv s }
  where s = padBlockSize (unKey key) $ B.concat $ L.toChunks $ compress $ encode a

lockAway :: BlockCipher k => Key k -> Keycard k -> IV k -> Keybox k
lockAway contentkey card@(Keycard { key, secret }) iv =
  Keybox $ M.singleton key (encrypt secret iv contentkey)

-- | Encrypt using a 'Keycard', storing the identity and the encrypted
-- content key
encryptAs :: (BlockCipher k, ToJSON a, FromJSON a) 
             => Key k -> IV k      -- ^ The content key and its 'IV'
             -> Keycard k -> IV k  -- ^ The 'Keycard' and its 'IV'
             -> a -> Encrypted k a -- ^ An 'Encrypted' producer
encryptAs contentkey ivcontent keycard ivcard a =
  (encrypt contentkey ivcontent a) {
    keys = Just $ lockAway contentkey keycard ivcontent
    }

addIdentity :: (BlockCipher k, ToJSON a)
               => Keycard k                      -- ^ An authorized identity
               -> Keycard k -> IV k              -- ^ The identity to add
               -> Encrypted k a -> Encrypted k a -- ^ An 'Encrypted' transformer
addIdentity = undefined

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
