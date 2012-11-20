{-# LANGUAGE DeriveGeneric #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

import Data.Encrypted
import Data.Encrypted.Internal

import Data.Aeson
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B

import GHC.Generics

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck


instance Arbitrary ByteString where
  arbitrary = B.pack `fmap` arbitrary

instance Arbitrary Text where
  arbitrary = T.pack `fmap` arbitrary

data Wrapper a = Wrapper { unWrap :: a } deriving (Show, Eq, Generic)

instance Arbitrary a => Arbitrary (Wrapper a) where
  arbitrary = fmap Wrapper arbitrary

instance ToJSON a => ToJSON (Wrapper a)
instance FromJSON a => FromJSON (Wrapper a)

-- | Only the left inverse is meaningful since the other inverse
-- doesn't have all of 'Text' as its domain, only valid base 64
-- strings!
ladj_b64text :: ByteString -> Bool
ladj_b64text bs = Just bs == unb64text (b64text bs)

ladj_json :: (FromJSON a, ToJSON a, Eq a) => a -> a -> Bool
ladj_json witness a =
  case decode (encode $ Wrapper $ a `asTypeOf` witness) of
    Nothing          -> False
    Just (Wrapper b) -> a == b

main :: IO ()
main = defaultMain tests

tests :: [Test]
tests = [
  testGroup "adjunctions" [
     testProperty "left b64text" ladj_b64text,
     testProperty "left JSON/Id" $ ladj_json (undefined :: Id),
     testProperty "left JSON/Key" $ ladj_json (undefined :: Key),
     testProperty "left JSON/Nonce" $ ladj_json (undefined :: Nonce),
     testProperty "left JSON/Encrypted" $ ladj_json (undefined :: Encrypted (Encrypted Int))
     ]
  ]