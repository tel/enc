{-# LANGUAGE OverloadedStrings #-}

module Data.Encrypted.JSON where

import Data.Encrypted

import Data.UUID
import Data.Aeson
import Data.Traversable
import           Data.Map (Map)
import qualified Data.Map as M hiding (keys)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as L8
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Text.Encoding as E
import           Data.Text.Lazy.Encoding as EL
import qualified Data.ByteString.Base64 as B64
import           Data.Serialize (Serialize)
import qualified Data.Serialize as S
import qualified Data.ByteString.Base64 as B64

import Crypto.Classes
import Crypto.Modes

import Control.Lens hiding ((.=))
import Control.Monad
import Control.Applicative
import Control.Error

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
           . M.mapKeys (EL.decodeUtf8 . toByteString)
           . M.map toJSON
           . getMap

-- GENERALLY we'd need a "traverse with key" or "traverse on the view
-- of pairs" solution here, since it's possible that parsing the
-- internal structure of the dictionary could fail.

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
    return Encrypted { _ivec = ivec,
                       _keys = keys,
                       _payload = payload }

instance (ToJSON a, BlockCipher k) => ToJSON (Encrypted k a) where
  toJSON e =
    object [ "ivec"    .= (stringFromSerializable $ view ivec e),
             "keys"    .= (toJSON $ view keys e),
             "paylaod" .= (stringFromSerializable $ view payload e) ]
