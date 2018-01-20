{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE BangPatterns #-}
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

import           Control.Concurrent (threadDelay,forkIO)
import           Control.Monad (forever)
import           Data.IORef
import           Data.Aeson
import qualified Data.HashMap.Strict as HM
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.ByteString.Char8 as B8
import           Data.List (intercalate)
import qualified Data.Set as Set
import           Data.Monoid
import           Text.Read (readMaybe)
import           Control.Monad.IO.Class
import           Network.HTTP.Simple hiding (Proxy)

import System.RandomString

data OAuthState
    = OAuthState (IORef ((Integer, Set.Set (Integer,Text))))
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
      | OAuthStateConfig { nonceLifetime :: Integer
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
    mv <- newIORef (0,mempty)
    let s = OAuthState mv
    _ <- forkIO $ collectGarbage s
    pure s
 where
  collectGarbage OAuthStateless = pure ()
  collectGarbage (OAuthState s) = forever $ do
       threadDelay (1000*1000*30) -- 30 seconds
       atomicModifyIORef s $ \(cnt,set) ->
           let tooOldCount = cnt - (nonceLifetime cfg `div` 30)
               !newCnt = cnt+1
               !(_,!newSet) = Set.split (tooOldCount,"") set
           in ((newCnt,newSet),())

newOAuthNonce :: MonadIO m => OAuthState -> m Text
newOAuthNonce OAuthStateless = pure ""
newOAuthNonce (OAuthState ref) =
  do rnd <- randomString StringOpts { alphabet=Base58, nrBytes = 24 }
     liftIO $ atomicModifyIORef ref $ \(counter,st) ->
        let state  = T.pack (show counter) <> "_" <> rnd
            !newSet = Set.insert (counter,rnd) st
        in ((counter,newSet),state)

-- Return true if the auth nonce is recent, valid, and removes it from the state
verifyOAuthNonce :: MonadIO m => OAuthState -> Maybe Text -> m Bool
verifyOAuthNonce OAuthStateless Nothing = pure True
verifyOAuthNonce OAuthStateless (Just _) = pure True -- we ignore state as not a nonce but it could be used by another part of the oauth system
verifyOAuthNonce (OAuthState _) Nothing = pure False
verifyOAuthNonce (OAuthState ref) (Just nonce) =
  do let nonceStructure :: (Integer,Text)
         nonceStructure = (\(a,b) -> (maybe (-1) id (readMaybe (T.unpack a)),T.drop 1 b)) (T.break (== '_') nonce)
     liftIO $ atomicModifyIORef ref $ \(counter,st) ->
        let !newSet = Set.delete nonceStructure st
        in ((counter,newSet), Set.member nonceStructure st)

-- Step 1. Take user to the service's auth page. Returns the URL for oauth to the
-- given provider.

-- | Acquire the URL, which includes the oauth state (a nonce), for the user
-- to log into the identified oauth provider and be redirected back to the
-- requesting server.
getAuthorize :: MonadIO m => OAuthState -> OAuth2 -> m Text
getAuthorize authSt oinfo = authEndpoint oinfo <$> newOAuthNonce authSt

-- Step 2. Accept a temporary code from the service

-- | Upon redirect there should be at least two parameters
--  * "code=<somecode>" which is handed to the provider to acquire a token.
--  * "state=<thestate>" which is checked to ensure it originated from the
--    getAuthorize call.
--
-- @getAuthorized provider authState codeParam stateParam@ verifies the state
-- is valid and not timed out, requests a token from the service provider
-- using the code, and returns the token obtained from the provider (or
-- @Nothing@ on failure).
getAuthorized :: MonadIO m => OAuth2 -> OAuthState -> Maybe Text -> Maybe Text -> m (Maybe Text)
getAuthorized _ _ Nothing _ = pure Nothing -- a 'code=' param is needed
getAuthorized prov authSt (Just code) retState =
  do b <- verifyOAuthNonce authSt retState
     if (not b) then pure Nothing
                else getAccessToken code prov

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
