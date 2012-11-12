{-# LANGUAGE DeriveDataTypeable,
             GADTs,
             OverloadedStrings,
             GeneralizedNewtypeDeriving,
             Rank2Types,
             NamedFieldPuns #-}

{- |
Module      : $Header$
Description : Encryption-as-functor, high-level encryption primitives
              wrapped around serialization
Copyright   : (c) 2012 Joseph Abrahamson
License     : MIT
Maintainer  : Joseph Abrahamson <me@jspha.com>
Stability   : unstable
Portability : non-portable

Most encryption libraries are intentionally very low-level with types
such as

> encrypt key :: ByteString -> ByteString

but, Data.Encrypted lifts this raw operation up into a typesafe one

> encrypt key :: Serialize a => a -> Encrypted a

(though, for my own purposes, I'm originally building it around Aeson,
so instead of a 'Serialize' instance we need a 'ToJSON' instance)

This typesafe encryption makes Encrypted into a kind of indexed
functor enabling pseudo-Homomorphic Encryption via lifting

> f :: a -> b
> liftM f :: Encrypted a -> Encrypted b

although the actual computation must be delayed until a valid key
(index) is provided.

-}

module Data.Encrypted (
  -- Encrypted (..),
  Key (..), -- newKey
  ) where

import Data.Data
import Data.UUID
import Data.Tagged
import Data.Aeson
import Data.Monoid
import Data.Aeson.Types (Parser)
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

import Crypto.Modes
import Crypto.Random
import Crypto.Classes hiding (encode)
import Crypto.Padding

import Test.QuickCheck
import Test.QuickCheck.Gen
import System.Random

import Codec.Compression.Zlib

import Control.Monad
import Control.Monad.Identity
import Control.Monad.Trans.Class
import Control.Monad.Trans.State
import Control.Applicative
import Control.Arrow
import Control.Error

-- | A newtype wrapper around 'UUID' since we need some new instances
-- not available in the raw type.
newtype Id = Id UUID
           deriving (Show, Eq, Ord, Data, Typeable)

instance Serialize Id where
  put (Id iv) = S.putByteString $ mconcat $ L.toChunks $ toByteString iv
  get = fmap (L.fromChunks . return) S.get
        >>= fmap Id . justZ . fromByteString

-- | Keys are always lifted from the raw crypto-api @forall
-- k. BlockCipher k => k@ up into a new 'Key' container. It's useful
-- both for providing custom instances on the 'k' type without using
-- XUndeciableInstances and XOverlappingInstances and also allows us
-- to give a 'UUID' name to every key.
data Key k = Key Id k deriving (Show, Eq, Data, Typeable)

-- | A box for putting 'IV k's, needed to derive encoding classes
-- without using XOverlappingInstances.
newtype Ivec k = Ivec (IV k) deriving (Show, Eq)

instance BlockCipher k => Serialize (Ivec k) where
  put (Ivec iv) = S.put iv
  get = fmap Ivec S.get

-- | A wrapper around the raw 'ByteString' serializations inside of an
-- 'Encrypted' box. Again, useful for writing encoding instances, but
-- it also has a phantom type tracking the encryption scheme used to
-- create it.
newtype Payload k = Payload ByteString
                deriving (Show, Eq, Data, Typeable)

-- | Passes through to the underlying 'ByteString'
-- transparently---there is no trace of the wrapper once serialized.
instance BlockCipher k => Serialize (Payload k) where
  put (Payload bs) = S.put bs
  get = fmap Payload S.get

-- | A 'Keymap' is a certificate noting what keys are able to decrypt
-- this particular encrypted box. They come in two forms, either a
-- single certificate (the 'Left' side) or a mapping from 'Id' to
-- 'Encrypted k (Key k)' which indicates that the content key is
-- stored in many different 'Encrypted' categories, each one indexed
-- by a particular 'Id => Key k'.
data Keymap k = Keymap (Either Id (Map Id (Encrypted k (Key k))))
                deriving (Show, Eq)

-- | An (almost) indexed functor into the 'Encrypted a'
-- category. There are two kinds of encrypted 
data Encrypted k a =
  Encrypted { ivec    :: Ivec k,
              keys    :: Keymap k,
              payload :: Payload k }
  deriving (Show, Eq)

-- | Tries to decrypt a given 'Encrypted a' using any of the provided
-- keys.
decrypt :: (FromJSON a, BlockCipher k) => Key k -> Encrypted k a -> Maybe a
decrypt
  (Key uuid key)
  (Encrypted { ivec = Ivec iv, payload = Payload payload }) =
    do msg <- unpadPKCS5safe out
       decode $ decompress $ L.fromChunks [msg]
  where (out, _) = unCbc' key iv payload

{- $rationale

A completely pure encryption operation would have to look like

> BlockCipher k => Key k -> IV k -> a -> Encrypted a

but this is actually a little bit unsafe: how can we be sure that the
initialization vector is being generated from a cryptographically
secure random source? We'd have to do it outselves, really, so instead
we have to wrap 'getIV' and do

> (BlockCipher k, CryptoRandomGen g) =>
> g -> Key k -> a -> (Encrypted a, g)

which looks like a 'State' monad of some sort or another.

To take it a step further, if we want to be able to lift functions via
an 'Encrypted'-like functor, then we'll need some more information

> liftE :: (BlockCipher k, CryptoRandomGen g) =>
>          Key k -> (a -> b) -> (Encrypted a -> (Encrypted b, g))
> liftE k f ~= encrypt k . f . decrypt k

where the 'Key k' is used for both encryption and decryption in a
'Reader'-like fashion.

These two features basically beg a Monad instance, but what kind of
monad is it?

> x :: Encrypt AES256 Int
> x = do addKey key
>        addKey key
>        removeKey key
>        return 3
> runEncryptIO x :: IO (Encrypted AES256 Int)
> encode . runEncryptIO :: ToJSON a => Encrypt k a -> IO ByteString

-}

data EncryptState g k = EncryptState StdGen g (Map Id (Key k))

-- | A monad transformer for building encryption pipelines and
-- methods.
newtype EncryptT g k m a =
  EncryptT (MaybeT (StateT (EncryptState g k) m) a)
  deriving (Functor, Applicative, Monad, MonadPlus)

type EncryptG g k a = EncryptT g k Identity a

instance MonadTrans (EncryptT g k) where
  lift = EncryptT . lift . lift

-- | Attempts to inject an 'Encrypted a' into the 'Encrypt' monad,
-- using the first included key which can decrypt the value, but fails
-- otherwise.
fromEncrypted :: (BlockCipher k, Monad m, CryptoRandomGen g, FromJSON a) =>
                 Encrypted k a -> EncryptT g k m a
fromEncrypted e = getKeys >>= justZ . fmap head . mapM (flip decrypt e) 

getKeys :: Monad m => EncryptT g k m [Key k]
getKeys = do EncryptState _ g0 es <- EncryptT $ lift get
             return (M.elems es)

getEState :: Monad m => EncryptT g k m (EncryptState g k)
getEState = EncryptT $ lift get

putEState :: Monad m => EncryptState g k -> EncryptT g k m ()
putEState s = EncryptT $ lift $ put s

modCGen :: Monad m => (g -> Maybe (a, g)) -> EncryptT g k m a
modCGen f = do EncryptState r g0 es <- getEState
               case f g0 of
                 Nothing -> nothing
                 Just (a, g1) -> do
                   putEState $ EncryptState r g1 es
                   just a

getNewCGen :: (Monad m, CryptoRandomGen g) => EncryptT g k m g
getNewCGen = modCGen (rightMay . splitGen)

modSGen :: Monad m => (StdGen -> (a, StdGen)) -> EncryptT g k m a
modSGen f = do EncryptState r0 g es <- getEState
               let (a, r1) = f r0
               putEState (EncryptState r1 g es)
               return a

getNewSGen :: (Monad m) => EncryptT g k m StdGen
getNewSGen = modSGen split

just :: Monad m => a -> EncryptT g k m a
just = EncryptT . return

nothing :: Monad m => EncryptT g k m a
nothing = EncryptT . MaybeT . return $ Nothing

newIvec :: (Monad m, BlockCipher k, CryptoRandomGen g) => EncryptT g k m (Ivec k)
newIvec = getNewCGen >>= rightZ . fmap (Ivec . fst) . getIV

-- | Creates a new cryptographic key
newKey :: (CryptoRandomGen g, BlockCipher k, Monad m) => EncryptT g k m (Key k)
newKey = do let len = keyLength
            k    <- modCGen (rightMay . genBytes (untag len)) >>= justZ . buildKey
            uuid <- modSGen random
            return (Key (Id uuid) (k `asTaggedTypeOf` len))

-- | Encrypt a value outside of an 'Encrypt' context
encrypt' :: (BlockCipher k, ToJSON a) => Key k -> Ivec k -> a -> Payload k
encrypt' (Key id k) (Ivec iv) a = Payload $ fst $ cbc' k iv bytes
  where bytes = padBlockSize k $ mconcat $ L.toChunks $ compress $ encode a

-- | Encrypt a value in the current 'Encrypt' context using a single
-- particular key
encryptOnce :: (BlockCipher k, Monad m, ToJSON a, CryptoRandomGen g) =>
               a -> Key k -> EncryptT g k m (Encrypted k a)
encryptOnce a key@(Key id k) =
  do ivec@(Ivec iv) <- newIvec
     return Encrypted { ivec    = ivec,
                        keys    = Keymap (Left id),
                        payload = encrypt' key ivec a }

-- | Encrypt a value in the current 'Encrypt' context
encrypt :: (ToJSON a, BlockCipher k, Monad m, CryptoRandomGen g) =>
           a -> EncryptT g k m (Encrypted k a)
encrypt a = do contentIvec          <- newIvec
               contentKey           <- newKey
               keys                 <- getKeys
               encryptedContentKeys <- mapM (encryptOnce contentKey) keys
               return Encrypted { ivec    = contentIvec,
                                  keys    = makeKeymap keys encryptedContentKeys,
                                  payload = encrypt' contentKey contentIvec a }
  where makeKeymap :: [Key k] -> [Encrypted k (Key k)] -> Keymap k
        makeKeymap keys encs = Keymap $ Right $ M.fromList $ zipWith go keys encs
        go :: Key k -> Encrypted k (Key k) -> (Id, Encrypted k (Key k))
        go (Key id _) e = (id, e)

performEncryptT :: (CryptoRandomGen g, Monad m, MonadPlus m) =>
                   StdGen -> g -> EncryptT g k m a -> m a
performEncryptT sg rg (EncryptT m) =
  evalStateT (runMaybeT m) (EncryptState sg rg M.empty) >>= justZ
                          
performEncryptTIO :: CryptoRandomGen g => EncryptT g k IO a -> IO a
performEncryptTIO e =
  do sg <- getStdGen
     rg <- newGenIO
     performEncryptT sg rg e
                                   
-- -- Serialization instances: JSON

instance FromJSON Id where
  parseJSON (String s) = fmap Id $ justZ $ fromString $ T.unpack s
  parseJSON _          = fail "parse: Data.Encrypted.JSON UUID"

instance ToJSON Id where
  toJSON (Id uuid) = String . T.pack . toString $ uuid

-- | A helper function which serializes any serializable value into a
-- JSON String
textFromSerializable :: Serialize a => a -> Text
textFromSerializable = E.decodeUtf8 . B64.encode . S.encode

-- | The inverse function of 'stringFromSerializable'
serializableFromText :: (Serialize a, MonadPlus m) => Text -> m a
serializableFromText t =
  rightZ . (S.decode <=< B64.decode) . E.encodeUtf8 $ t

instance BlockCipher k => ToJSON (Key k) where
  toJSON (Key id k) = object ["key" .= (String $ textFromSerializable k),
                              "id"  .= toJSON id]

instance BlockCipher k => ToJSON (Payload k) where
  toJSON (Payload bs) = String . E.decodeUtf8 . B64.encode $ bs

instance BlockCipher k => FromJSON (Payload k) where
  parseJSON (String s) = fmap Payload $ rightZ $ B64.decode $ E.encodeUtf8 s
  parseJSON _          = fail "parse: Data.Encrypted.JSON Payload"

instance BlockCipher k => FromJSON (Key k) where
  parseJSON (Object o) = do
    key <- (o .: "key") >>= serializableFromText
    id  <- o .: "id"
    return (Key id key)

instance BlockCipher k => ToJSON (Keymap k) where
  toJSON (Keymap (Left id)) =
    object ["owner" .= toJSON id]
  toJSON (Keymap (Right m)) = object [("keys", object $ pairs m)]
    where pairs :: BlockCipher k => Map Id (Encrypted k (Key k)) -> [(Text, Value)]
          pairs = map (toText *** toJSON) . M.toList
          toText :: Id -> Text
          toText = textFromSerializable

-- | Traverses on the map as a list, so it could be faster if it were
-- in-place instead of having to deconstruct and rebuild the map
-- through an intermediary
instance BlockCipher k => FromJSON (Keymap k) where
  parseJSON v = objParse v single <|> objParse v multi
    where objParse :: Value -> (Object -> Parser a) -> Parser a
          objParse (Object o) f = f o
          objParse _          _ = fail "parse Data.Encrypted.Keymap not an object"
          -- | Parse a single type Keymap
          single   :: BlockCipher k => Object -> Parser (Keymap k)
          single o = do
            id <- o .: "owner"
            return $ Keymap $ Left id
          -- | Parse a multi type Keymap
          multi    :: BlockCipher k => Object -> Parser (Keymap k)
          multi o = do
            keys <- o .: "keys"
            pairs <- mapM (runKleisli doKey) keys
            return $ Keymap $ Right $ M.fromList pairs
            where doKey :: BlockCipher k =>
                           Kleisli Parser (Text, Value) (Id, Encrypted k (Key k))
                  doKey = Kleisli serializableFromText *** Kleisli parseJSON

instance (ToJSON a, BlockCipher k) => ToJSON (Encrypted k a) where
  toJSON (Encrypted { ivec, keys, payload }) =
    object [ "ivec"    .= (String $ textFromSerializable ivec),
             "keys"    .= toJSON keys,
             "payload" .= (String $ textFromSerializable payload) ]
                   
instance (FromJSON a, BlockCipher k) => FromJSON (Encrypted k a) where
  parseJSON (Object o) = do
    ivec    <- o .: "ivec" >>= serializableFromText
    keys    <- o .: "keys"
    payload <- o .: "payload" >>= serializableFromText
    return Encrypted { ivec = ivec,
                       keys = keys,
                       payload = payload }
  parseJSON _ = fail "parse: Data.Encrypted FromJSON Encrypted"


-- -- Arbitrary instances

-- -- | Newtype entirely to form the Arbitrary instance
-- newtype Pair k = P (Key k, Keymap k)

-- instance (BlockCipher k) => Arbitrary (Pair k) where
--   arbitrary = do
--     contentkey <- arbitrary
--     key        <- arbitrary
--     iv         <- arbitrary
--     uuid       <- arbitrary
--     let keyType = Key (Id uuid) key
--     return $ P (keyType, lockAway contentkey keyType iv)

-- instance BlockCipher k => Arbitrary (Key k) where
--   arbitrary = fmap (fst . unPair) arbitrary

-- instance BlockCipher k => Arbitrary (Keybox k) where
--   arbitrary = fmap (snd . unPair) arbitrary

-- -- | Lifts 'UUID's 'Random' instance
-- instance Arbitrary Id where
--   arbitrary = MkGen $ \g _ -> Id $ fst $ random g

-- instance BlockCipher k => Arbitrary (Ivec k) where
--   arbitrary = do
--     ent <- vector $ unTagged (genSeedLength :: Tagged HashDRBG Int)
--     let Right g0 = newGen (B.pack ent)
--         Right (iv, _) = getIV (g0 :: HashDRBG)
--     return (Ivec iv)

-- -- | NOT CRYPTOGRAPHICALLY SECURE!
-- instance BlockCipher k => Arbitrary (Key k) where
--   arbitrary =
--     do let l = keyLength
--        Just k <- fmap (buildKey . B.pack) (vector $ untag $ l `div` 8)
--        return (Key $ asTaggedTypeOf k l)