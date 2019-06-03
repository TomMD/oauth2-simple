{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase   #-}
{-# LANGUAGE TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
-- | A simple OAuth2 implementation with nonce state to prevent forgery attacks.
--
-- Originally based on [frekletonj](https://gist.github.com/freckletonj/17eec8959718cb251f29af3645112f4a)'s
-- oauth gist, this library should be simple and fast enough for moderate use.
module Network.OAuth2
    ( -- * Construct an oauth state
      newOAuthState, newOAuthStateWith
      -- * Default configurations
    , oauthStateless, oauthStateNonce
      -- * Typical client endpoints
    , getAuthorize, getAuthorized
      -- * Types
    , OAuthStateConfig(..)
    , OAuth2(..), OAuthState
    ) where

import           Data.Aeson
import qualified Data.Binary     as Bin
import qualified Data.Binary.Get as Bin
import qualified Data.Binary.Put as Bin
import qualified Data.HashMap.Strict as HM
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Time (NominalDiffTime)
import           Data.Time.Clock.POSIX
import qualified Data.ByteString.Char8 as B8
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import           Data.List (intercalate)
import           Control.Monad.IO.Class
import           Crypto.Hash.SHA256 (hmac)
import           Network.HTTP.Simple hiding (Proxy)
import           Crypto.Util (constTimeEq)
import           System.Entropy (getEntropy, getHardwareEntropy)

import qualified Data.ByteString.Base58 as B58

-- | An hmac key used to prevent cross site request forgeries.
newtype AntiCSRFKey = AntiCSRFKey ByteString

data OAuthState
    = OAuthState { oasKey  :: AntiCSRFKey
                 , oasLife :: NominalDiffTime
                 }
    | OAuthStateless

data OAuth2 = OAuth2 { oauthClientId :: Text
                     , oauthClientSecret :: Text
                     , oauthOAuthorizeEndpoint :: Text
                     , oauthAccessTokenEndpoint :: Text
                     , oauthCallback :: Text
                     , oauthScopes :: [Scope]
                     } deriving (Show, Eq)

type Scope = Text

renderScopes :: [Scope] -> Text
renderScopes = T.pack . intercalate "," . map T.unpack

----------

authEndpoint :: OAuth2 -> Text -> Text
authEndpoint oa theState =
  mconcat $ [ oauthOAuthorizeEndpoint oa
            , "?client_id=", oauthClientId oa
            , "&response_type=", "code"
            , "&redirect_uri=", oauthCallback oa
            , "&scope=", renderScopes (oauthScopes oa) ]
             <> if T.length theState > 0
                then [ "&state=", theState ]
                else mempty

tokenEndpoint :: Text -> OAuth2 -> Text
tokenEndpoint code oa = mconcat [ oauthAccessTokenEndpoint oa
                                , "?client_id=", oauthClientId oa
                                , "&client_secret=", oauthClientSecret oa
                                , "&code=", code
                                ]

----------

data OAuthStateConfig
      = OAuthStatelessConfig
      | OAuthStateConfig { nonceLifetime :: NominalDiffTime
                         -- Time from URL generation that login can occur
                         -- (seconds).  This lifetime is only enforced
                         -- approximately.
                         }

oauthStateNonce :: OAuthStateConfig
oauthStateNonce = OAuthStateConfig { nonceLifetime = (10*60) }

oauthStateless :: OAuthStateConfig
oauthStateless = OAuthStatelessConfig

-- Step 0. Get an auth state so redirects won't work

-- |Obtain a new OAuth state.
--
-- In oauth terms: Each resource owner needs a state, a set of valid nonces,
-- to validate oauth requests.  When an application authenticates to the oauth
-- provider this state is included to eliminate forgery attacks.
newOAuthState :: MonadIO m => m OAuthState
newOAuthState = newOAuthStateWith oauthStateless

newOAuthStateWith :: MonadIO m => OAuthStateConfig -> m OAuthState
newOAuthStateWith OAuthStatelessConfig = pure OAuthStateless
newOAuthStateWith cfg = liftIO $ do
    let fastRandom nr = maybe (getEntropy nr) pure =<< getHardwareEntropy nr
    key <- AntiCSRFKey <$> fastRandom 32
    pure OAuthState { oasKey = key, oasLife = nonceLifetime cfg }

data Nonce a = Nonce { _nonceExpires :: a
                     , _nonceHMAC    :: ByteString
                     }

instance Bin.Binary a => Bin.Binary (Nonce a) where
    put (Nonce e h) = Bin.put e >> Bin.putByteString h
    get = Nonce <$> Bin.get <*> (LBS.toStrict <$> Bin.getRemainingLazyByteString)

newOAuthNonce :: MonadIO m => OAuthState -> ByteString -> m Text
newOAuthNonce OAuthStateless aad = pure $ T.decodeUtf8 $ B58.encodeBase58 B58.bitcoinAlphabet $ aad
newOAuthNonce (OAuthState key time) aad =
  do expire <- addTime time <$> getTime
     let tag = hmacTime key (expire,aad)
     let nonce = Nonce (expire,aad) tag
     let ser = T.decodeUtf8 . B58.encodeBase58 B58.bitcoinAlphabet
             . LBS.toStrict . Bin.encode
     pure (ser nonce)

hmacTime :: Bin.Binary a => AntiCSRFKey -> a -> ByteString
hmacTime (AntiCSRFKey key) = hmac key . LBS.toStrict . Bin.encode

-- Return the authenticated data if the auth nonce is recent and valid. Nothing
-- otherwise.
verifyOAuthNonce :: MonadIO m => OAuthState -> Maybe Text -> m (Maybe ByteString)
verifyOAuthNonce OAuthStateless Nothing = pure Nothing
verifyOAuthNonce OAuthStateless (Just _) = pure Nothing -- we ignore state as not a nonce but it could be used by another part of the oauth system
verifyOAuthNonce (OAuthState {}) Nothing = pure Nothing
verifyOAuthNonce (OAuthState key _time) (Just nonceText) =
  case B58.decodeBase58 B58.bitcoinAlphabet (T.encodeUtf8 nonceText) >>= decodeMay . LBS.fromStrict of
    Nothing -> pure Nothing
    Just (Nonce (expire,aad) tag) ->
      do now <- liftIO getTime
         if now > expire
            then pure Nothing
            else if constTimeEq tag (hmacTime key (expire,aad))
                    then pure (Just aad)
                    else pure Nothing
 where
 decodeMay = either (const Nothing) (\(_,_,x) -> Just x) . Bin.decodeOrFail

data MyTime = MyTime POSIXTime
    deriving (Eq,Ord,Show)

addTime :: NominalDiffTime -> MyTime -> MyTime
addTime d (MyTime t) = MyTime (d + t)

getTime :: MonadIO m => m MyTime
getTime = MyTime <$> liftIO getPOSIXTime

instance Bin.Binary MyTime where
   put (MyTime t) = Bin.put (realToFrac t :: Double)
   get = MyTime . (realToFrac :: Double -> POSIXTime) <$> Bin.get

-- Step 1. Take user to the service's auth page. Returns the URL for oauth to the
-- given provider.

-- | Acquire the URL, which includes the oauth state (a nonce), for the user
-- to log into the identified oauth provider and be redirected back to the
-- requesting server.
getAuthorize :: MonadIO m => OAuthState -> OAuth2 -> ByteString -> m Text
getAuthorize authSt oinfo aad =
      authEndpoint oinfo <$> newOAuthNonce authSt aad

-- Step 2. Accept a temporary code from the service

-- | Upon redirect there should be at least two parameters
--  * "code=<somecode>" which is handed to the provider to acquire a token.
--  * "state=<thestate>" which is checked to ensure it originated from the
--    getAuthorize call.
--
-- @getAuthorized provider authState codeParam stateParam@ verifies the state
-- is valid and not timed out, requests a token from the service provider
-- using the code, and returns the token obtained from the provider and any
-- additional authenticated data passed from the oauth state from
-- @getAuthorize@ (or @Nothing@ on failure).
getAuthorized :: MonadIO m => OAuth2 -> OAuthState -> Maybe Text -> Maybe Text -> m (Maybe (Text,ByteString))
getAuthorized _ _ Nothing _ = pure Nothing -- a 'code=' param is needed
getAuthorized prov authSt (Just code) retState =
  verifyOAuthNonce authSt retState >>= \case
    Nothing  -> pure Nothing
    Just aad -> fmap (,aad) <$> getAccessToken code prov

-- Step 3. Exchange code for auth token

-- | After the client has logged into the provider, been redirected to the
-- authorized address and provided the state and code parameters the server
-- may acquire a token from the oauth provider.
getAccessToken :: MonadIO m => Text -> OAuth2 -> m (Maybe Text)
getAccessToken code prov = liftIO $ do
  let endpoint = tokenEndpoint code prov
  request' <- parseRequest (T.unpack endpoint)
  let justText = Just . B8.pack . T.unpack
      request = setRequestMethod "POST"
                $ addRequestHeader "Accept" "application/json"
                $ setRequestQueryString [ ("client_id", justText . oauthClientId $ prov)
                                        , ("client_secret", justText . oauthClientSecret $ prov)
                                        , ("code", justText code)]
                $ request'
  response <- httpJSONEither request
  return $ case (getResponseBody response :: Either JSONException Object) of
             Left _    -> Nothing
             Right obj -> case HM.lookup "access_token" obj of
                            Just (String x) -> Just x
                            _ -> Nothing
