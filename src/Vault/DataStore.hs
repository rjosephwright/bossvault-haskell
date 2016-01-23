{-# LANGUAGE OverloadedStrings #-}
module Vault.DataStore
       (
         store
       , retrievePayload
       , retrieveKey
       ) where

import Control.Exception
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.List
import System.Directory
import Vault.Types

import Debug.Trace

baseDir :: FilePath
baseDir = "bossvault"

filePath :: [String] -> FilePath
filePath parts = intercalate "/" parts

dirPath :: Account -> Role -> Artifact -> FilePath
dirPath account role artifact = filePath [baseDir, account, role, artifact]

keyPath :: Account -> Role -> Artifact -> FilePath
keyPath account role artifact = filePath [dirPath account role artifact,  "key"]

payloadPath :: Account -> Role -> Artifact -> FilePath
payloadPath account role artifact = filePath [dirPath account role artifact, "data"]

-- Behaves like 'mkdir -p' except it throws an error if the final directory to be
-- created already exists.
mkdir :: String -> IO ()
mkdir dir = mkdirs $ descendingPaths dir
  where mkdirs [final] = createDirectory final
        mkdirs (d:ds) = createDirectoryIfMissing False d >> mkdirs ds
        mkdirs [] = return ()

-- Takes a pathname and returns a list of all of its parent directories
-- in descending order:
--
-- descendingPaths "path/to/some/file"
-- [
--   "path",
--   "path/to",
--   "path/to/some",
--   "path/to/some/file"
-- ]
descendingPaths :: FilePath -> [String]
descendingPaths path =
  let parts = groupBy (\_ b -> b /= '/') path in
  [concat $ fst $ splitAt n parts | n <- [1..length parts]] 

store :: Account -> Role -> Artifact -> ByteString -> ByteString -> IO ()
store account role artifact encrypted key =
  let dir = dirPath account role artifact
      p = payloadPath account role artifact
      k = keyPath account role artifact in
  do bracketOnError
       (mkdir dir)
       (\_ -> removeDirectoryRecursive dir)
       (\_ -> do
           BS.writeFile p encrypted
           BS.writeFile k key)

retrievePayload :: Account -> Role -> Artifact -> IO ByteString
retrievePayload account role artifact = BS.readFile $ payloadPath account role artifact

retrieveKey :: Account -> Role -> Artifact -> IO ByteString
retrieveKey account role artifact = BS.readFile $ keyPath account role artifact
