
module Data.Encrypted.Internal where

import Data.Aeson
import Data.Monoid
import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base64 as B64

import Control.Error

-- | Strict JSON encode
encodeS :: ToJSON a => a -> ByteString
encodeS = mconcat . BL.toChunks . encode

-- | Strict JSON decode
decodeS :: FromJSON a => ByteString -> Maybe a
decodeS = decode . BL.fromChunks . return

b64text :: ByteString -> Text
b64text = TE.decodeUtf8 . B64.encode

unb64text :: Text -> Maybe ByteString
unb64text = rightMay . B64.decode . TE.encodeUtf8
