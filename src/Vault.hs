{-# LANGUAGE DeriveDataTypeable, OverloadedStrings, ScopedTypeVariables #-}
module Vault where

import Control.Error.Safe
import Control.Error.Util
import Control.Exception (Exception)
import qualified Control.Exception as E
import Control.Lens hiding ((??))
import Control.Monad
import Control.Monad.Except
import Control.Monad.Trans
import Control.Monad.Trans.AWS
import Control.Monad.Trans.Except
import Control.Monad.Trans.Maybe
import Control.Monad.Trans.Resource
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import qualified Crypto.Data.Padding as P
import Crypto.Error
import Crypto.Random
import Data.ByteArray (ByteArray)
import qualified Data.ByteArray as BA
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Char
import Data.Data
import Data.List
import Data.Maybe
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Network.AWS hiding (send)
import Network.AWS.KMS.CreateAlias
import Network.AWS.KMS.CreateKey
import Network.AWS.KMS.GenerateDataKey
import Network.AWS.KMS.ListAliases
import Network.AWS.KMS.ListKeys
import Network.AWS.KMS.Types
import System.Environment
import System.IO

import Vault.Aws
import Vault.Pure
import Vault.Types

data VaultError = IVError deriving (Show, Typeable)

instance Exception VaultError

kms :: AwsAction ListKeysResponse
kms = send listKeys

keyIdForAlias :: KeyAlias -> AwsAction (Maybe KeyId)
keyIdForAlias alias = do
  a <- send listAliases
  return $ keyIdForAliasP a alias

-- TODO: handle pagination
filterKeys :: KeyId -> AwsAction (Maybe KeyListEntry)
filterKeys keyId = do
  k <- send listKeys
  return $ filterKeysP k keyId

-- TODO: handle pagination
filterAliases :: KeyAlias -> AwsAction (Maybe AliasListEntry)
filterAliases alias = do
  a <- send listAliases
  return $ filterAliasesP a alias

findOrCreateMasterKey :: KeyAlias -> AwsAction KeyId
findOrCreateMasterKey alias = do
  as <- send listAliases
  case keyIdForAliasP as alias of
    Just keyId -> return keyId
    Nothing -> do
      rs <- send createKey
      keyId <- lift $ keyIdP rs ?? "Missing key metadata."
      void $ send $ createAlias alias keyId
      pure keyId

dataKey :: KeyAlias -> AwsAction GenerateDataKeyResponse
dataKey alias = do
  keyId <- findOrCreateMasterKey alias
  send $ generateDataKey keyId

encrypt :: (ByteArray ba, Show ba, Exception e) => ba -> ba -> (ExceptT e IO ba)
encrypt key bytes = do
  r <- getRandomBytes 16
  iv <- (makeIV r :: Maybe (IV AES256)) ?? IVError
  cipher <- lift $ cipherInit key
  b <- BA.append r $ encrypted cipher iv
  return $ eitherCryptoError b
    where
      p c = padded bytes $ blockSize c
      encrypted c i = cbcEncrypt c i (p c)

decrypt :: (ByteArray ba, Show ba) => ba -> ba -> IO ba
decrypt key bytes = do
  let (r, blob) = BA.splitAt 16 bytes
  return $ case makeIV r :: Maybe (IV AES256) of
    Nothing -> E.throw IVError
    Just iv ->
      case cipherInit key of
        CryptoFailed e -> E.throw e
        CryptoPassed cipher -> fromMaybe decrypted u
          where
            decrypted = cbcDecrypt cipher iv blob
            format = P.PKCS7 $ blockSize cipher
            u = P.unpad format decrypted

padded :: (ByteArray ba) => ba -> Int -> ba
padded bytes bs =
  case BA.length bytes `mod` bs of
    0 -> bytes
    _ -> P.pad format bytes where
      format = P.PKCS7 bs
