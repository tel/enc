{-# LANGUAGE DeriveDataTypeable,
             DeriveGeneric,
             GeneralizedNewtypeDeriving,
             OverloadedStrings #-}

{- |
Module      : $Header$

Description : Encryption as functor. A typesafe way to use NaCl's
              high-level secret key cryptosystem.

Copyright   : (c) 2012 Joseph Abrahamson
License     : MIT
Maintainer  : Joseph Abrahamson <me@jspha.com>
Stability   : experimental
Portability : non-portable

-}

module Data.Encrypted (
  Id           (..),
  Key          (..),
  Nonce        (..),
  Ownership    (..),
  Encrypted    (..),
  EncryptError (..),
  EncryptT, performEncrypt, performEncrypt',
  Encrypt,
  fromEncrypted,
  newKey, getKeys,
  addKey, removeKey, removeKeyById,
  encrypt, encryptMulti, decrypt
  ) where

import Data.Encrypted.Internal

import Data.UUID
import Data.Aeson
import Data.Tagged
import Data.Maybe
import Data.Monoid
import Data.List
import qualified Data.Text as T
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base64 as B64

import GHC.Generics
import Data.Data

import Crypto.NaCl.Key
import Crypto.NaCl.Random
import qualified Crypto.NaCl.Internal as SaltI
import qualified Crypto.NaCl.Encrypt.SecretKey as SK

import Control.Error
import Control.Applicative
import Control.Arrow
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.Class
import Control.Monad.Trans.State
import Control.Monad.Trans.Error

import System.Random
import Test.QuickCheck
import Test.QuickCheck.Gen

-- | 'Id's are encryption identities, wrappers around random
-- "Data.UUID.UUID" which helps for Serialization purposes.
newtype Id = Id { unId :: UUID } deriving (Eq, Ord, Data, Typeable, Generic)

instance Show Id where
  show (Id {unId = uuid}) = "Id " ++ show uuid

-- | 'UUID's are serialized directly, but since we known the UUID
-- character set is valid ASCII, it's safe to just directly encode it
instance ToJSON Id where
  toJSON = String . T.pack . toString . unId

-- | 'UUID's are deserialized directly. Similar to the 'ToJSON'
-- instance, we assume the character set is fine and encode directly.
instance FromJSON Id where
  parseJSON (String t) =
    justZ . fmap Id . fromString . T.unpack $ t
  parseJSON _ = mzero

-- | Lifts the 'Random UUID' instance
instance Arbitrary Id where
  arbitrary = fmap Id $ MkGen $ \g _ -> fst (random g)



data Key = Key { key :: SecretKey, identity :: Id }
           deriving (Eq, Typeable, Generic)

instance Show Key where
  showsPrec p (Key { identity = i }) =
    showParen (p>0) $
    showString $ "Key {key = <<elided>>, identity = " ++ show i ++ "}"


instance ToJSON Key where
  toJSON (Key { key = SecretKey kbs, identity = i }) =
    object ["key"      .= String (b64text kbs),
            "identity" .= toJSON i]
            
instance FromJSON Key where
  parseJSON (Object o) =
    do i            <- o .: "identity"
       (String ktx) <- o .: "key"
       kbs          <- justZ $ unb64text ktx
       return Key { key = SecretKey kbs, identity = i }
  parseJSON _ = mzero

-- | WARNING For testing only! This does not produce cryptographically
-- random keys!
instance Arbitrary Key where
  arbitrary = do k <- fmap (SecretKey . B.pack) $ vector SK.keyLength
                 i <- arbitrary
                 return Key { key = k, identity = i }

-- | A newtype wrapper around 'SK.SKNonce' for serialization
newtype Nonce = Nonce SK.SKNonce deriving (Eq, Typeable, Generic)

instance Show Nonce where
  showsPrec p (Nonce sk) =
    showParen (p>0) $
    showString (B8.unpack $ "Nonce " <> B64.encode (SaltI.toBS sk))

-- | Lift the internal 'Nonce' API up to 'Nonce'
instance SaltI.Nonce Nonce where
  size = retag (SaltI.size :: Tagged SK.SKNonce Int)
  toBS (Nonce n) = SaltI.toBS n
  fromBS bs = fmap Nonce $ SaltI.fromBS bs
  createZeroNonce = Nonce SaltI.createZeroNonce
  createRandomNonce = fmap Nonce SaltI.createRandomNonce
  incNonce (Nonce n) = Nonce (SaltI.incNonce n)

instance ToJSON Nonce where
  toJSON (Nonce n) = String . b64text $ SaltI.toBS n

instance FromJSON Nonce where
  parseJSON (String t) = justZ $ SaltI.fromBS <=< unb64text $ t
  parseJSON _ = mzero

instance Arbitrary Nonce where
  arbitrary =
    do let size = SaltI.size
       n <- fmap (fromJust . SaltI.fromBS . B.pack) (vector $ untag size)
       return (n `asTaggedTypeOf` size)

data Ownership = Single Id | Multi [Encrypted Key]
               deriving (Show, Eq, Typeable, Generic)

instance ToJSON Ownership where
  toJSON (Single i)  = object ["one"  .= toJSON i]
  toJSON (Multi  is) = object ["many" .= toJSON is]

instance FromJSON Ownership where
  parseJSON (Object o) = singleParse <|> multiParse
    where singleParse = fmap Single $ o .: "one"
          multiParse  = fmap Multi  $ o .: "many"
  parseJSON _ = mzero

data Encrypted a =
  Encrypted { payload :: ByteString,
              nonce   :: Nonce,
              ownedBy :: Ownership }
  deriving (Eq, Show, Typeable, Generic)

instance ToJSON   (Encrypted a)
instance FromJSON (Encrypted a)

instance (Arbitrary a, ToJSON a) => Arbitrary (Encrypted a) where
  arbitrary =
    do a                              <- arbitrary
       n@(Nonce skn)                  <- arbitrary
       (Key { key = k, identity = i}) <- arbitrary
       return $ encryptedAsTypeOf a 
         Encrypted { payload = B64.encode $ SK.encrypt skn (encodeS a) k,
                     nonce   = n,
                     ownedBy = Single i }
    where encryptedAsTypeOf :: a -> Encrypted a -> Encrypted a
          encryptedAsTypeOf _ e = e

data EncryptError = EncryptError
                  | OtherEncryptError String
                  | NoKeys
                  | NotAuthorized
                  | PayloadEncodingFailure
                  | SignatureFailure
                  | DecodeFailure
                  deriving (Show, Eq, Ord)

instance Error EncryptError where
  noMsg  = EncryptError
  strMsg = OtherEncryptError

-- | A monad transformer for building encryption pipelines and
-- methods. Within a single 'EncryptT' session, 'Nonce's are
-- guaranteed to be randomized and increasing.
newtype EncryptT m a =
  EncryptT (ErrorT EncryptError (StateT ([Key], Nonce) m) a)
  deriving (Functor, Applicative, Monad, MonadPlus, MonadIO)

instance Monad m => Monoid (EncryptT m a) where
  mempty = mzero
  mappend = mplus

-- | A synonym for when the transformer isn't stacked
type Encrypt a = EncryptT IO a

instance MonadTrans EncryptT where
  lift = EncryptT . lift . lift

-- | Attempts to inject an 'Encrypted a' into the 'Encrypt' monad,
-- using the first included key which can decrypt the value, but fails
-- otherwise.
fromEncrypted :: Encrypted a -> EncryptT m a
fromEncrypted = undefined

errd :: Monad m => EncryptError -> EncryptT m a
errd = EncryptT . throwError

-- | Gets the active keys inside of this 'EncryptT'
getKeys :: Monad m => EncryptT m [Key]
getKeys = EncryptT $ liftM fst $ lift get

addKey :: Monad m => Key -> EncryptT m ()
addKey k = EncryptT $ lift $ modify $ first (k:)

pickKey :: Monad m => Id -> EncryptT m Key
pickKey i = do keys <- getKeys
               case find (\k -> identity k == i) keys of
                 Nothing -> errd NotAuthorized
                 Just k  -> return k

removeKey :: Monad m => Key -> EncryptT m ()
removeKey k = EncryptT $ lift $ modify $ first f
  where f :: [Key] -> [Key]
        f = filter (/= k)

removeKeyById :: Monad m => Id -> EncryptT m ()
removeKeyById i = EncryptT $ lift $ modify $ first f
  where f :: [Key] -> [Key]
        f = filter (\k -> identity k /= i)

newKey :: MonadIO m => EncryptT m Key
newKey = do bs <- liftIO (randomBytes SK.keyLength)
            i  <- liftIO randomIO
            return Key { key = SecretKey bs, identity = Id i }

newNonce :: Monad m => EncryptT m Nonce
newNonce = do n <- EncryptT $ liftM snd $ lift get
              EncryptT $ lift $ modify $ second SaltI.incNonce
              return n

-- | Encrypts a payload using a fresh nonce and a given key
encrypt :: (Monad m, ToJSON a) => Key -> a -> EncryptT m (Encrypted a)
encrypt (Key {key = k, identity = i}) a =
  do n@(Nonce skn) <- newNonce
     return Encrypted { payload = B64.encode $ SK.encrypt skn (encodeS a) k,
                        nonce   = n,
                        ownedBy = Single i }

-- | Encrypts a payload using all of the currently available keys
encryptMulti :: (MonadIO m, ToJSON a) => a -> EncryptT m (Encrypted a)
encryptMulti a = do keys <- getKeys
                    case keys of
                      []     -> errd NoKeys
                      (x:[]) -> encrypt x a
                      xs     -> do contentKey <- newKey
                                   enc        <- encrypt contentKey a
                                   certs      <- mapM (`encrypt` contentKey) xs
                                   return enc { ownedBy = Multi certs }

decrypt :: (Monad m, FromJSON a) => Encrypted a -> EncryptT m a
decrypt (Encrypted { ownedBy = o,
                     nonce = Nonce skn,
                     payload = p }) =
  case o of
    Single i    -> do (Key { key = sk }) <- pickKey i
                      decrypt' sk
    Multi encks -> do (Key { key = sk }) <- mconcat $ map decrypt encks
                      decrypt' sk
  where decrypt' sk =
          do pl <- (rightZ $ B64.decode p)      <> errd PayloadEncodingFailure
             s  <- justZ (SK.decrypt skn pl sk) <> errd SignatureFailure
             a  <- justZ (decodeS s)            <> errd DecodeFailure
             return a

-- | Runs an 'EncryptT'
performEncrypt :: MonadIO m => EncryptT m a -> m (Either EncryptError a)
performEncrypt (EncryptT m) =
  do n <- liftIO SaltI.createRandomNonce
     evalStateT (runErrorT m) ([], n)

-- | Like 'performEncrypt' but just passes failure into the base monad
performEncrypt' :: (MonadIO m, MonadPlus m) => EncryptT m a -> m a
performEncrypt' e = performEncrypt e >>= rightZ
