{-# LANGUAGE DeriveGeneric #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

import Data.Encrypted
import Data.Encrypted.Internal

import Data.Aeson
import Data.List
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64

import GHC.Generics

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck
import Test.QuickCheck.Monadic

import Control.Monad

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
ladj_json _ a =
  case decode (encode $ Wrapper a) of
    Nothing          -> False
    Just (Wrapper b) -> a == b

ladj_encrypt :: (Eq a, ToJSON a, FromJSON a) => a -> a -> Property
ladj_encrypt _ a =
  monadicIO $ do a' <- run $ performEncrypt'
                       $ do k <- newKey
                            e <- encrypt k a
                            addKey k
                            decrypt e
                 assert (a' == a)

ladj_encryptMulti :: (Eq a, ToJSON a, FromJSON a) => a -> a -> Property
ladj_encryptMulti _ a =
  monadicIO $ do a' <- run $ performEncrypt'
                       $ do k <- newKey
                            addKey k                            
                            e <- encryptMulti a
                            decrypt e
                 assert (a' == a)

prop_signatureCheck :: (Eq a, ToJSON a, FromJSON a) => a -> a -> Property
prop_signatureCheck _ a =
  monadicIO $ do a' <- run $ performEncrypt
                       $ do k <- newKey
                            addKey k                            
                            e <- encryptMulti a
                            decrypt (tamperWith e)
                 assert $ check a a'
  where tamperWith e@(Encrypted { payload = bs }) =
          e { payload = B64.encode $ B.map (+1) (fromRight $ B64.decode bs) }
        fromRight (Right x) = x
        fromRight _ = error "error: fromRight, Properties.hs"
        check :: a -> Either EncryptError a -> Bool
        check _ (Left SignatureFailure) = True
        check _ _ = False

prop_newNonceCollisions :: Property
prop_newNonceCollisions = monadicIO $ do n1 <- run getNonce
                                         n2 <- run getNonce
                                         assert (n1 /= n2)
  where getNonce =
          fmap nonce $ performEncrypt'
          $ newKey >>= (`encrypt` (Wrapper True))

prop_internalNonceCollisions :: Property
prop_internalNonceCollisions =
  monadicIO $ do ns <- run $ getNonces 50
                 assert (areUnique ns)
  where getNonces n = performEncrypt' $ do
          k <- newKey
          replicateM n $ fmap nonce $ encrypt k (Wrapper True)
        areUnique xs = length xs == length (nub xs)

main :: IO ()
main = defaultMain tests

tests :: [Test]
tests = [
  testGroup "adjunctions" [
     testProperty "left b64text" ladj_b64text,

     testGroup "left JSON" [
       testProperty "Id" $ ladj_json (undefined :: Id),
       testProperty "Key" $ ladj_json (undefined :: Key),
       testProperty "Nonce" $ ladj_json (undefined :: Nonce),
       testProperty "Encrypted" $ ladj_json (undefined :: Encrypted (Encrypted Int))
       ],
     
     testGroup "left Encrypt" [
       testProperty "Wrapped Int" $ ladj_encrypt (undefined :: Wrapper Int),
       testProperty "Encrypted Wrapped Int"
       $ ladj_encrypt (undefined :: Encrypted (Wrapper Int)),
       
       testGroup "Multi Encrypt" [
         testProperty "left EncryptMulti/WrappedInt"
         $ ladj_encryptMulti (undefined :: Wrapper Int),
         testProperty "left EncryptMulti/EncryptedWrappedInt"
         $ ladj_encryptMulti (undefined :: Encrypted (Wrapper Int))
         ]
       ]
     ],

  testGroup "attacks" [
    testProperty "tampering" $ prop_signatureCheck (undefined :: Wrapper Int),
    testGroup "nonce collision" [
      testProperty "independent" prop_newNonceCollisions,
      testProperty "internal" prop_internalNonceCollisions
      ]
    ]
  ]