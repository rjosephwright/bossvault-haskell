module Vault.Aws where

import Control.Exception
import Control.Lens
import Control.Monad
import Control.Monad.Trans.AWS
import Control.Monad.Trans.Except
import Control.Monad.Trans.Resource
import Data.Char
import Data.List
import Data.Maybe
import Data.Text (Text)
import qualified Data.Text as T
import Data.Typeable
import Network.AWS.KMS.Types
import System.Environment
import System.IO

type AwsAction a = AWST (ExceptT String (ResourceT IO)) a

lookupWithDefault :: String -> [(String, a)] -> a -> a
lookupWithDefault s m d = fromMaybe d (lookup (map toLower s) m)

fromEnv :: String -> (String -> a) -> IO a
fromEnv s resolver = lookupEnv s >>= \e -> return $ resolver (fromMaybe "" e)

logLevelResolver :: String -> LogLevel
logLevelResolver s = lookupWithDefault s m Debug
  where m = [("info", Info),
             ("error", Error),
             ("debug", Debug),
             ("trace", Trace)]

regionResolver :: String -> Region
regionResolver s = lookupWithDefault s m NorthVirginia
  where m = [("eu-west-1", Ireland),
             ("eu-central-1", Frankfurt),
             ("ap-northeast-1", Tokyo),
             ("ap-southeast-1", Singapore),
             ("ap-southeast-2", Sydney),
             ("cn-north-1", Beijing),
             ("us-east-1", NorthVirginia),
             ("us-west-1", NorthCalifornia),
             ("us-west-2", Oregon),
             ("us-gov-west-1", GovCloud),
             ("fips-us-gov-west-1", GovCloudFIPS),
             ("sa-east-1", SaoPaulo)]

fromEnvLogLevel :: IO LogLevel
fromEnvLogLevel = fromEnv "BOSSVAULT_LOG_LEVEL" logLevelResolver

fromEnvRegion :: IO Region
fromEnvRegion = fromEnv "BOSSVAULT_REGION" regionResolver

inAws :: AWST' Env (ResourceT IO) a -> IO a
inAws action = do
  ll <- fromEnvLogLevel
  l <- newLogger ll stdout
  r <- fromEnvRegion
  env <- newEnv r Discover <&> envLogger .~ l
  runResourceT . runAWST env $ action
