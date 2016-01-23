module Vault.Pure where

import Control.Lens
import Data.List
import Data.Text (Text)
import qualified Data.Text as T
import Network.AWS.KMS.CreateKey
import Network.AWS.KMS.ListAliases
import Network.AWS.KMS.ListKeys
import Network.AWS.KMS.Types
import Vault.Types

keyIdForAliasP :: ListAliasesResponse -> KeyAlias -> Maybe KeyId
keyIdForAliasP listAliasesResponse alias =
  case filter matches (listAliasesResponse ^. larsAliases) of
    (a:_) -> a ^. aleTargetKeyId
    [] -> Nothing
    where matches a = a ^. aleAliasName == (Just fullAlias)
          fullAlias = T.concat [T.pack "alias/", alias]

keyIdP :: CreateKeyResponse -> Maybe KeyId
keyIdP createKeyResponse = createKeyResponse ^? ckrsKeyMetadata . traverse . kmKeyId

filterKeysP :: ListKeysResponse -> KeyId -> Maybe KeyListEntry
filterKeysP listKeysResponse keyId =
  find (\k -> k ^. kleKeyId == Just keyId) (listKeysResponse ^. lkrsKeys)

filterAliasesP :: ListAliasesResponse -> KeyAlias -> Maybe AliasListEntry
filterAliasesP listAliasesResponse alias =
  find (\a -> a ^. aleAliasName == Just alias) (listAliasesResponse ^. larsAliases)
